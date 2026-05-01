#pragma once

#include <QAbstractScrollArea>
#include <QReadWriteLock>
#include <cstdint>
#include <unordered_set>

class HexView : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit HexView(QWidget* parent = nullptr);

    void setData(const uint8_t* data, size_t size);
    void clear();

    void setDiffOffsets(const std::unordered_set<size_t>* offsets);
    void setDiffLock(QReadWriteLock* lock);

    size_t cursorOffset() const { return static_cast<size_t>(m_cursorPos); }

signals:
    void offsetSelected(size_t offset);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    void updateMetrics();
    void updateScrollRange();
    void paintRow(QPainter& painter, int row);
    int rowFromPos(const QPoint& pos) const;
    int byteColFromPos(const QPoint& pos) const;
    void setCursor(int bytePos);

    const uint8_t* m_data = nullptr;
    size_t m_size = 0;

    int m_bytesPerRow = 16;
    int m_rowHeight = 0;
    int m_charWidth = 0;
    int m_offsetWidth = 0;
    int m_hexStartX = 0;
    int m_asciiStartX = 0;

    int m_cursorPos = 0;
    int m_selectionAnchor = -1;
    int m_selectionStart = 0;
    int m_selectionEnd = 0;

    const std::unordered_set<size_t>* m_diffOffsets = nullptr;
    QReadWriteLock* m_diffLock = nullptr;
};
