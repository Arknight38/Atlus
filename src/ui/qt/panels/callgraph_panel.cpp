#include "callgraph_panel.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextBrowser>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QFileInfo>

CallGraphPanel::CallGraphPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(5);
    layout->setContentsMargins(8, 8, 8, 8);

    // Toolbar
    auto* toolbar = new QHBoxLayout();
    m_statusLabel = new QLabel("No call graph loaded", this);
    m_statusLabel->setStyleSheet("color: #888;");
    toolbar->addWidget(m_statusLabel);
    toolbar->addStretch();

    m_refreshBtn = new QPushButton("Refresh", this);
    m_refreshBtn->setEnabled(false);
    connect(m_refreshBtn, &QPushButton::clicked, this, &CallGraphPanel::onRefreshClicked);
    toolbar->addWidget(m_refreshBtn);

    m_saveBtn = new QPushButton("Save SVG...", this);
    m_saveBtn->setEnabled(false);
    connect(m_saveBtn, &QPushButton::clicked, this, &CallGraphPanel::onSaveClicked);
    toolbar->addWidget(m_saveBtn);

    layout->addLayout(toolbar);

    // SVG viewer
    m_viewer = new QTextBrowser(this);
    m_viewer->setPlaceholderText("Enable rev.ng call graph generation to view the program-wide call graph.\n\n"
                                  "The call graph will be rendered as an interactive SVG from rev.ng's render-svg-call-graph command.");
    layout->addWidget(m_viewer);
}

void CallGraphPanel::setSVG(const QString& svg)
{
    m_currentSVG = svg;

    // Display SVG content (as text for now - full SVG rendering requires additional handling)
    // For a proper implementation, we could use QSvgWidget or embed in HTML
    if (svg.startsWith("<?xml") || svg.startsWith("<svg")) {
        // Embed in HTML for display
        QString html = QString("<html><body>%1</body></html>").arg(svg);
        m_viewer->setHtml(html);
        m_statusLabel->setText("Call graph loaded");
        m_statusLabel->setStyleSheet("color: #4CAF50;");
    } else {
        m_viewer->setPlainText(svg);
        m_statusLabel->setText("Raw call graph data");
    }

    m_refreshBtn->setEnabled(true);
    m_saveBtn->setEnabled(true);
}

void CallGraphPanel::setStatus(const QString& status)
{
    m_statusLabel->setText(status);
}

void CallGraphPanel::clear()
{
    m_currentSVG.clear();
    m_viewer->clear();
    m_statusLabel->setText("No call graph loaded");
    m_statusLabel->setStyleSheet("color: #888;");
    m_refreshBtn->setEnabled(false);
    m_saveBtn->setEnabled(false);
}

void CallGraphPanel::onRefreshClicked()
{
    emit requestCallGraph();
}

void CallGraphPanel::onSaveClicked()
{
    if (m_currentSVG.isEmpty()) {
        QMessageBox::warning(this, "Save Error", "No call graph to save.");
        return;
    }

    QString path = QFileDialog::getSaveFileName(
        this, "Save Call Graph SVG", "callgraph.svg",
        "SVG files (*.svg);;All files (*)");

    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Save Error", "Failed to open file for writing.");
        return;
    }

    QTextStream stream(&file);
    stream << m_currentSVG;
    file.close();

    m_statusLabel->setText("Saved to " + QFileInfo(path).fileName());
}
