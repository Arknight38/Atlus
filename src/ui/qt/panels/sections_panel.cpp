#include "sections_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QHeaderView>

SectionsPanel::SectionsPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    m_model = new SectionsModel(this);

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

void SectionsPanel::setSections(const std::vector<atlus::PESection>& sections)
{
    m_model->setData(sections);
    m_view->resizeColumnsToContents();
}

void SectionsPanel::clear()
{
    m_model->clear();
}
