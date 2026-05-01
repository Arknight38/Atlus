#include "aob_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QHeaderView>

AobPanel::AobPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    m_model = new AobModel(this);

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
    m_view->setFont(QFont("Consolas", 10));
    layout->addWidget(m_view);
}

void AobPanel::setSignatures(const std::vector<atlus::AobSignature>& signatures)
{
    m_model->setSignatures(signatures);
    m_view->resizeColumnsToContents();
}

void AobPanel::clear()
{
    m_model->clear();
}
