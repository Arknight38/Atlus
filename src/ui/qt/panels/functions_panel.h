#pragma once

#include <QWidget>
#include <QSortFilterProxyModel>
#include "models/functions_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
class QLineEdit;
QT_END_NAMESPACE

class FunctionsPanel : public QWidget {
    Q_OBJECT

public:
    explicit FunctionsPanel(QWidget* parent = nullptr);

    FunctionsModel* model() const { return m_model; }
    void setFunctions(const std::vector<atlus::Function>& functions);
    void clear();

signals:
    void functionSelected(const atlus::Function* fn);

private:
    FunctionsModel* m_model = nullptr;
    QSortFilterProxyModel* m_proxy = nullptr;
    QTableView* m_view = nullptr;
    QLineEdit* m_filter = nullptr;
};
