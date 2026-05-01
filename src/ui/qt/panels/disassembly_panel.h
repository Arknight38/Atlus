#pragma once

#include <QWidget>
#include "models/disassembly_model.h"

QT_BEGIN_NAMESPACE
class QTableView;
QT_END_NAMESPACE

class DisassemblyPanel : public QWidget {
    Q_OBJECT

public:
    explicit DisassemblyPanel(QWidget* parent = nullptr);

    void setInstructions(const std::vector<atlus::Instruction>& instructions);
    void clear();

signals:
    void instructionSelected(const atlus::Instruction* ins);

private:
    DisassemblyModel* m_model = nullptr;
    QTableView* m_view = nullptr;
};
