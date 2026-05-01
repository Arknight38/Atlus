#pragma once

#include <QWidget>
#include "models/imports_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
QT_END_NAMESPACE

class ImportsPanel : public QWidget {
    Q_OBJECT

public:
    explicit ImportsPanel(QWidget* parent = nullptr);

    void setImports(const std::vector<atlus::ImportEntry>& imports);
    void clear();

private:
    ImportsModel* m_model = nullptr;
    QTableView* m_view = nullptr;
};
