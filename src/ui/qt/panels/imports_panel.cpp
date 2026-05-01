#include "imports_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QHeaderView>

ImportsPanel::ImportsPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    m_model = new ImportsModel(this);

    m_view = new QTableView(this);
    m_view->setModel(m_model);
    m_view->setSortingEnabled(true);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_view->horizontalHeader()->setStretchLastSection(true);
    m_view->verticalHeader()->setVisible(false);
    m_view->setAlternatingRowColors(true);
    m_view->setShowGrid(false);
    m_view->setWordWrap(false);
    layout->addWidget(m_view);
}

void ImportsPanel::setImports(const std::vector<atlus::ImportEntry>& imports)
{
    m_model->setData(imports);
    m_view->resizeColumnsToContents();
}

void ImportsPanel::clear()
{
    m_model->clear();
}
