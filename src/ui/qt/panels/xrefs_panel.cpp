#include "xrefs_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QTabWidget>
#include <QHeaderView>
#include <QItemSelectionModel>

XrefsPanel::XrefsPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    auto* tabs = new QTabWidget(this);

    m_callersModel = new XrefsModel(this);
    m_callersView = new QTableView(this);
    m_callersView->setModel(m_callersModel);
    m_callersView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_callersView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_callersView->horizontalHeader()->setStretchLastSection(true);
    m_callersView->verticalHeader()->setVisible(false);
    m_callersView->setAlternatingRowColors(true);
    m_callersView->setShowGrid(false);
    m_callersView->setWordWrap(false);
    tabs->addTab(m_callersView, "Callers");

    connect(m_callersView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) {
                if (!current.isValid()) return;
                QString addrStr = m_callersModel->data(m_callersModel->index(current.row(), 0), Qt::DisplayRole).toString();
                emit xrefSelected(addrStr.toULongLong(nullptr, 16));
            });

    m_calleesModel = new XrefsModel(this);
    m_calleesView = new QTableView(this);
    m_calleesView->setModel(m_calleesModel);
    m_calleesView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_calleesView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_calleesView->horizontalHeader()->setStretchLastSection(true);
    m_calleesView->verticalHeader()->setVisible(false);
    m_calleesView->setAlternatingRowColors(true);
    m_calleesView->setShowGrid(false);
    m_calleesView->setWordWrap(false);
    tabs->addTab(m_calleesView, "Callees");

    connect(m_calleesView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) {
                if (!current.isValid()) return;
                emit xrefSelected(m_calleesModel->data(m_calleesModel->index(current.row(), 0), Qt::DisplayRole).toString().toULongLong(nullptr, 16));
            });

    layout->addWidget(tabs);
}

void XrefsPanel::setCallers(const std::vector<atlus::XRef>& xrefs)
{
    m_callersModel->setXrefs(xrefs, XrefsModel::Callers);
    m_callersView->resizeColumnsToContents();
}

void XrefsPanel::setCallees(const std::vector<atlus::XRef>& xrefs)
{
    m_calleesModel->setXrefs(xrefs, XrefsModel::Callees);
    m_calleesView->resizeColumnsToContents();
}

void XrefsPanel::clear()
{
    m_callersModel->clear();
    m_calleesModel->clear();
}
