#include "sections_model.h"

SectionsModel::SectionsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void SectionsModel::setData(const std::vector<atlus::PESection>& sections)
{
    beginResetModel();
    m_sections = sections;
    endResetModel();
}

void SectionsModel::clear()
{
    beginResetModel();
    m_sections.clear();
    endResetModel();
}

int SectionsModel::rowCount(const QModelIndex&) const
{
    return static_cast<int>(m_sections.size());
}

int SectionsModel::columnCount(const QModelIndex&) const
{
    return 6; // Name, VAddr, VSize, RawOff, RawSize, Flags
}

QVariant SectionsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_sections.size()))
        return QVariant();

    const auto& sec = m_sections[static_cast<size_t>(index.row())];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case 0: return QString::fromStdString(sec.name);
            case 1: return QString("0x%1").arg(sec.vaddr, 8, 16, QLatin1Char('0'));
            case 2: return QString("0x%1").arg(sec.vsize, 8, 16, QLatin1Char('0'));
            case 3: return QString("0x%1").arg(sec.raw_offset, 8, 16, QLatin1Char('0'));
            case 4: return QString("0x%1").arg(sec.raw_size, 8, 16, QLatin1Char('0'));
            case 5: return QString("0x%1").arg(sec.flags, 8, 16, QLatin1Char('0'));
            default: return QVariant();
        }
    }

    if (role == Qt::TextAlignmentRole) {
        if (index.column() == 0) return Qt::AlignLeft;
        return Qt::AlignRight;
    }

    return QVariant();
}

QVariant SectionsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
        case 0: return QStringLiteral("Name");
        case 1: return QStringLiteral("VAddr");
        case 2: return QStringLiteral("VSize");
        case 3: return QStringLiteral("RawOff");
        case 4: return QStringLiteral("RawSize");
        case 5: return QStringLiteral("Flags");
        default: return QVariant();
    }
}
