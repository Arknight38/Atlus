#include "functions_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QLineEdit>
#include <QHeaderView>
#include <QItemSelectionModel>

FunctionsPanel::FunctionsPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    // Filter box
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText("Filter functions...");
    layout->addWidget(m_filter);

    // Table view
    m_model = new FunctionsModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(0); // Name column

    m_view = new QTableView(this);
    m_view->setModel(m_proxy);
    m_view->setSortingEnabled(true);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::SingleSelection);
    m_view->horizontalHeader()->setStretchLastSection(true);
    m_view->verticalHeader()->setVisible(false);
    m_view->setAlternatingRowColors(true);
    m_view->setShowGrid(false);
    m_view->setWordWrap(false);
    layout->addWidget(m_view);

    // Filter signal
    connect(m_filter, &QLineEdit::textChanged,
            m_proxy, &QSortFilterProxyModel::setFilterFixedString);

    // Selection signal
    connect(m_view->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) {
                if (!current.isValid()) return;
                auto srcIdx = m_proxy->mapToSource(current);
                auto* fn = m_model->functionAt(srcIdx.row());
                if (fn) emit functionSelected(fn);
            });
}

void FunctionsPanel::setFunctions(const std::vector<atlus::Function>& functions)
{
    m_model->setData(functions);
    m_view->resizeColumnsToContents();
}

void FunctionsPanel::clear()
{
    m_model->clear();
}
