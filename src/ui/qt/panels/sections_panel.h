#pragma once

#include <QWidget>
#include "models/sections_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
QT_END_NAMESPACE

class SectionsPanel : public QWidget {
    Q_OBJECT

public:
    explicit SectionsPanel(QWidget* parent = nullptr);

    void setSections(const std::vector<atlus::PESection>& sections);
    void clear();

private:
    SectionsModel* m_model = nullptr;
    QTableView* m_view = nullptr;
};
