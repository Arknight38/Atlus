#include "cfg_panel.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QFont>

CFGPanel::CFGPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(5);
    layout->setContentsMargins(8, 8, 8, 8);

    // Toolbar
    auto* toolbar = new QHBoxLayout();
    m_statusLabel = new QLabel("No CFG loaded", this);
    m_statusLabel->setStyleSheet("color: #888;");
    toolbar->addWidget(m_statusLabel);
    toolbar->addStretch();

    m_refreshBtn = new QPushButton("Refresh", this);
    m_refreshBtn->setEnabled(false);
    connect(m_refreshBtn, &QPushButton::clicked, this, &CFGPanel::onRefreshClicked);
    toolbar->addWidget(m_refreshBtn);

    layout->addLayout(toolbar);

    // CFG display
    m_editor = new QPlainTextEdit(this);
    m_editor->setReadOnly(true);
    m_editor->setFont(QFont("JetBrains Mono", 10));
    m_editor->setPlaceholderText("Select a function and enable rev.ng CFG generation to view the Control Flow Graph.\n\n"
                                  "The CFG will be displayed as structured YAML from rev.ng's emit-cfg command.");
    layout->addWidget(m_editor);
}

void CFGPanel::setCFG(const QString& yaml, uint64_t address)
{
    m_currentAddress = address;
    m_editor->setPlainText(yaml);
    m_statusLabel->setText(QString("CFG for 0x%1").arg(address, 0, 16));
    m_statusLabel->setStyleSheet("color: #4CAF50;");
    m_refreshBtn->setEnabled(true);
}

void CFGPanel::setStatus(const QString& status)
{
    m_statusLabel->setText(status);
}

void CFGPanel::clear()
{
    m_currentAddress = 0;
    m_editor->clear();
    m_statusLabel->setText("No CFG loaded");
    m_statusLabel->setStyleSheet("color: #888;");
    m_refreshBtn->setEnabled(false);
}

void CFGPanel::onRefreshClicked()
{
    if (m_currentAddress != 0) {
        emit requestCFG(m_currentAddress);
    }
}
