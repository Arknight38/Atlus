#include "hex_panel.h"
#include <QVBoxLayout>

HexPanel::HexPanel(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(0);
    layout->setContentsMargins(0, 0, 0, 0);

    m_view = new HexView(this);
    layout->addWidget(m_view);
}
