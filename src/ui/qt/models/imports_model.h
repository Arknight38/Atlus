#pragma once

#include <QAbstractTableModel>
#include <vector>
#include <string>
#include "core/pe_parser.h"

class ImportsModel : public QAbstractTableModel {
    Q_OBJECT

public:
    struct FlatImport {
        QString dll;
        QString function;
    };

    explicit ImportsModel(QObject* parent = nullptr);

    void setData(const std::vector<atlus::ImportEntry>& imports);
    void clear();

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<FlatImport> m_imports;
};
