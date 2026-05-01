#include "imports_model.h"

ImportsModel::ImportsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void ImportsModel::setData(const std::vector<atlus::ImportEntry>& imports)
{
    beginResetModel();
    m_imports.clear();
    for (const auto& entry : imports) {
        QString dll = QString::fromStdString(entry.dll);
        for (const auto& fn : entry.functions) {
            m_imports.push_back({dll, QString::fromStdString(fn)});
        }
    }
    endResetModel();
}

void ImportsModel::clear()
{
    beginResetModel();
    m_imports.clear();
    endResetModel();
}

int ImportsModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_imports.size());
}

int ImportsModel::columnCount(const QModelIndex&) const
{
    return 2; // DLL, Function
}

QVariant ImportsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_imports.size()))
        return QVariant();

    const auto& imp = m_imports[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return imp.dll;
            case 1: return imp.function;
            default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        return Qt::AlignLeft;
    }

    return QVariant();
}

QVariant ImportsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
        case 0: return QStringLiteral("DLL");
        case 1: return QStringLiteral("Function");
        default: return QVariant();
    }
}
