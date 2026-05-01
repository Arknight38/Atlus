#include "settings_dialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QDialogButtonBox>

void AppSettings::load(QSettings& s)
{
    revngPath = s.value("revngPath", QString()).toString();
    fontSize = s.value("fontSize", 13).toInt();
    autoFindFunctions = s.value("autoFindFunctions", true).toBool();
}

void AppSettings::save(QSettings& s) const
{
    s.setValue("revngPath", revngPath);
    s.setValue("fontSize", fontSize);
    s.setValue("autoFindFunctions", autoFindFunctions);
}

SettingsDialog::SettingsDialog(const AppSettings& current, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("Settings");
    resize(500, 200);

    auto* layout = new QVBoxLayout(this);

    // revng path
    auto* pathLayout = new QHBoxLayout();
    pathLayout->addWidget(new QLabel("rev.ng path:"));
    m_revngPathEdit = new QLineEdit(current.revngPath, this);
    pathLayout->addWidget(m_revngPathEdit);
    auto* browseBtn = new QPushButton("Browse...", this);
    connect(browseBtn, &QPushButton::clicked, this, &SettingsDialog::browseRevngPath);
    pathLayout->addWidget(browseBtn);
    layout->addLayout(pathLayout);

    // font size
    auto* fontLayout = new QHBoxLayout();
    fontLayout->addWidget(new QLabel("Font size:"));
    m_fontSizeSpin = new QSpinBox(this);
    m_fontSizeSpin->setRange(8, 32);
    m_fontSizeSpin->setValue(current.fontSize);
    fontLayout->addWidget(m_fontSizeSpin);
    fontLayout->addStretch();
    layout->addLayout(fontLayout);

    // auto-find functions
    m_autoFindCheck = new QCheckBox("Auto-find functions on load", this);
    m_autoFindCheck->setChecked(current.autoFindFunctions);
    layout->addWidget(m_autoFindCheck);

    layout->addStretch();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

AppSettings SettingsDialog::settings() const
{
    AppSettings s;
    s.revngPath = m_revngPathEdit->text();
    s.fontSize = m_fontSizeSpin->value();
    s.autoFindFunctions = m_autoFindCheck->isChecked();
    return s;
}

void SettingsDialog::browseRevngPath()
{
    QString path = QFileDialog::getOpenFileName(
        this, "Select rev.ng binary", QString(),
        "Executables (*.exe);;All files (*)");
    if (!path.isEmpty())
        m_revngPathEdit->setText(path);
}
