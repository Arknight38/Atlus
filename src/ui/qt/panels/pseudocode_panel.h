#pragma once

#include <QWidget>

QT_BEGIN_NAMESPACE
class QPlainTextEdit;
QT_END_NAMESPACE

class PseudocodePanel : public QWidget {
    Q_OBJECT
public:
    explicit PseudocodePanel(QWidget* parent = nullptr);
    void setText(const QString& text);
    void clear();
private:
    QPlainTextEdit* m_editor = nullptr;
};
