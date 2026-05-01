#pragma once

#include <QAbstractTableModel>
#include <vector>
#include "core/pe_parser.h"

class SectionsModel : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit SectionsModel(QObject* parent = nullptr);

    void setData(const std::vector<atlus::PESection>& sections);
    void clear();

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<atlus::PESection> m_sections;
};
