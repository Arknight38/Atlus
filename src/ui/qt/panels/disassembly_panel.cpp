#include "disassembly_panel.h"

#include <QVBoxLayout>
#include <QTableView>
#include <QHeaderView>
#include <QItemSelectionModel>

DisassemblyPanel::DisassemblyPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(2);
    layout->setContentsMargins(2, 2, 2, 2);

    m_model = new DisassemblyModel(this);

    m_view = new QTableView(this);
    m_view->setModel(m_model);
    m_view->setSortingEnabled(false);
    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::SingleSelection);
    m_view->horizontalHeader()->setStretchLastSection(true);
    m_view->verticalHeader()->setVisible(false);
    m_view->setAlternatingRowColors(true);
    m_view->setShowGrid(false);
    m_view->setWordWrap(false);
    m_view->setFont(QFont("Consolas", 10));
    layout->addWidget(m_view);

    connect(m_view->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) {
                if (!current.isValid()) return;
                auto* ins = m_model->instructionAt(current.row());
                if (ins) emit instructionSelected(ins);
            });
}

void DisassemblyPanel::setInstructions(const std::vector<atlus::Instruction>& instructions)
{
    m_model->setInstructions(instructions);
    m_view->resizeColumnsToContents();
}

void DisassemblyPanel::clear()
{
    m_model->clear();
}
