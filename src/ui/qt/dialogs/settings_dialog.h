#pragma once

#include <QDialog>
#include <QSettings>

QT_BEGIN_NAMESPACE
class QLineEdit;
class QSpinBox;
class QCheckBox;
QT_END_NAMESPACE

struct AppSettings {
    QString revngPath;
    int fontSize = 13;
    bool autoFindFunctions = true;

    void load(QSettings& s);
    void save(QSettings& s) const;
};

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(const AppSettings& current, QWidget* parent = nullptr);

    AppSettings settings() const;

private:
    void browseRevngPath();

    QLineEdit*  m_revngPathEdit = nullptr;
    QSpinBox*   m_fontSizeSpin = nullptr;
    QCheckBox*  m_autoFindCheck = nullptr;
};
