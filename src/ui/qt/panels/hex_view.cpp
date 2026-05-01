#include "hex_view.h"
#include "theme.h"

#include <QPainter>
#include <QFontMetrics>
#include <QScrollBar>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QWheelEvent>

HexView::HexView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    setFont(QFont("Consolas", 10));
    updateMetrics();
    setFocusPolicy(Qt::StrongFocus);
    viewport()->setCursor(Qt::IBeamCursor);
}

void HexView::setData(const uint8_t* data, size_t size)
{
    m_data = data;
    m_size = size;
    m_cursorPos = 0;
    m_selectionAnchor = -1;
    m_selectionStart = 0;
    m_selectionEnd = 0;
    updateScrollRange();
    viewport()->update();
}

void HexView::clear()
{
    m_data = nullptr;
    m_size = 0;
    m_cursorPos = 0;
    updateScrollRange();
    viewport()->update();
}

void HexView::setDiffOffsets(const std::unordered_set<size_t>* offsets)
{
    m_diffOffsets = offsets;
    viewport()->update();
}

void HexView::setDiffLock(QReadWriteLock* lock)
{
    m_diffLock = lock;
}

void HexView::updateMetrics()
{
    QFontMetrics fm(font());
    m_charWidth = fm.horizontalAdvance('0');
    m_rowHeight = fm.height() + 2;

    m_offsetWidth = m_charWidth * 12;  // "00000000:  "
    m_hexStartX = m_offsetWidth;
    m_asciiStartX = m_hexStartX + m_charWidth * (m_bytesPerRow * 3 + 2);
}

void HexView::updateScrollRange()
{
    int rows = static_cast<int>((m_size + m_bytesPerRow - 1) / m_bytesPerRow);
    int visibleRows = viewport()->height() / m_rowHeight;
    verticalScrollBar()->setRange(0, qMax(0, rows - visibleRows + 1));
    verticalScrollBar()->setSingleStep(1);
    verticalScrollBar()->setPageStep(visibleRows);
}

void HexView::paintEvent(QPaintEvent* event)
{
    QPainter painter(viewport());
    painter.setFont(font());

    int firstRow = verticalScrollBar()->value();
    int lastRow = firstRow + (viewport()->height() / m_rowHeight) + 2;

    int y = 2;
    for (int row = firstRow; row <= lastRow; ++row) {
        if (row * m_bytesPerRow >= static_cast<int>(m_size) && m_size > 0)
            break;
        paintRow(painter, row);
        y += m_rowHeight;
    }
}

void HexView::paintRow(QPainter& painter, int row)
{
    int y = (row - verticalScrollBar()->value()) * m_rowHeight + m_rowHeight - 4;
    size_t baseOffset = static_cast<size_t>(row) * m_bytesPerRow;

    // Background for row
    QRect rowRect(0, y - m_rowHeight + 4, viewport()->width(), m_rowHeight);
    if (row % 2 == 0)
        painter.fillRect(rowRect, Theme::color(Theme::HexAltRow));
    else
        painter.fillRect(rowRect, Theme::color(Theme::Background));

    // Offset
    painter.setPen(Theme::color(Theme::HexOffset));
    painter.drawText(4, y, QString("%1  ").arg(baseOffset, 8, 16, QLatin1Char('0')));

    // Read lock for diff offsets
    QReadLocker lock(m_diffLock ? m_diffLock : nullptr);

    for (int col = 0; col < m_bytesPerRow; ++col) {
        size_t offset = baseOffset + static_cast<size_t>(col);
        if (offset >= m_size) break;

        int xHex = m_hexStartX + col * m_charWidth * 3;
        int xAscii = m_asciiStartX + col * m_charWidth;

        bool selected = (offset >= static_cast<size_t>(m_selectionStart) &&
                         offset < static_cast<size_t>(m_selectionEnd));
        bool cursorHere = (offset == static_cast<size_t>(m_cursorPos));
        bool diffHere = m_diffOffsets && m_diffOffsets->count(offset);

        if (selected) {
            QRect selRect(xHex - 2, y - m_rowHeight + 4, m_charWidth * 2 + 4, m_rowHeight);
            painter.fillRect(selRect, Theme::color(Theme::HexSelection));
            QRect asciiSel(xAscii - 1, y - m_rowHeight + 4, m_charWidth + 2, m_rowHeight);
            painter.fillRect(asciiSel, Theme::color(Theme::HexSelection));
        } else if (diffHere) {
            QRect diffRect(xHex - 2, y - m_rowHeight + 4, m_charWidth * 2 + 4, m_rowHeight);
            painter.fillRect(diffRect, Theme::color(Theme::HexDiff));
        } else if (cursorHere) {
            QRect curRect(xHex - 2, y - m_rowHeight + 4, m_charWidth * 2 + 4, m_rowHeight);
            painter.fillRect(curRect, Theme::color(Theme::HexCursor));
        }

        // Hex byte
        uint8_t b = m_data[offset];
        painter.setPen(selected ? QColor("#ffffff") : Theme::color(Theme::HexText));
        painter.drawText(xHex, y, QString("%1").arg(b, 2, 16, QLatin1Char('0')));

        // ASCII
        char ch = (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
        painter.drawText(xAscii, y, QString(QLatin1Char(ch)));
    }
}

int HexView::rowFromPos(const QPoint& pos) const
{
    return verticalScrollBar()->value() + (pos.y() / m_rowHeight);
}

int HexView::byteColFromPos(const QPoint& pos) const
{
    int x = pos.x() - m_hexStartX;
    if (x < 0) return -1;
    int col = x / (m_charWidth * 3);
    if (col < 0 || col >= m_bytesPerRow) return -1;
    int rem = x % (m_charWidth * 3);
    if (rem > m_charWidth * 2 + 2) return -1;
    return col;
}

void HexView::setCursor(int bytePos)
{
    if (bytePos < 0) bytePos = 0;
    if (bytePos > static_cast<int>(m_size)) bytePos = static_cast<int>(m_size);
    m_cursorPos = bytePos;
    emit offsetSelected(static_cast<size_t>(bytePos));
    viewport()->update();
}

void HexView::mousePressEvent(QMouseEvent* event)
{
    if (!m_data || event->button() != Qt::LeftButton) return;

    int row = rowFromPos(event->pos());
    int col = byteColFromPos(event->pos());
    if (col < 0) col = 0;

    int bytePos = row * m_bytesPerRow + col;
    if (bytePos < 0) bytePos = 0;
    if (bytePos > static_cast<int>(m_size)) bytePos = static_cast<int>(m_size);

    m_selectionAnchor = bytePos;
    m_selectionStart = bytePos;
    m_selectionEnd = bytePos + 1;
    setCursor(bytePos);
}

void HexView::keyPressEvent(QKeyEvent* event)
{
    if (!m_data) return;

    int step = m_bytesPerRow;
    int newPos = m_cursorPos;

    switch (event->key()) {
        case Qt::Key_Left:  newPos = qMax(0, m_cursorPos - 1); break;
        case Qt::Key_Right: newPos = qMin(static_cast<int>(m_size) - 1, m_cursorPos + 1); break;
        case Qt::Key_Up:    newPos = qMax(0, m_cursorPos - step); break;
        case Qt::Key_Down:  newPos = qMin(static_cast<int>(m_size) - 1, m_cursorPos + step); break;
        case Qt::Key_PageUp:   newPos = qMax(0, m_cursorPos - step * 10); break;
        case Qt::Key_PageDown: newPos = qMin(static_cast<int>(m_size) - 1, m_cursorPos + step * 10); break;
        case Qt::Key_Home: newPos = (m_cursorPos / step) * step; break;
        case Qt::Key_End:  newPos = qMin(static_cast<int>(m_size) - 1, (m_cursorPos / step) * step + step - 1); break;
        default:
            QAbstractScrollArea::keyPressEvent(event);
            return;
    }

    m_selectionStart = newPos;
    m_selectionEnd = newPos + 1;
    setCursor(newPos);
}

void HexView::wheelEvent(QWheelEvent* event)
{
    verticalScrollBar()->setValue(verticalScrollBar()->value() - event->angleDelta().y() / 40);
}

void HexView::resizeEvent(QResizeEvent*)
{
    updateMetrics();
    updateScrollRange();
}
