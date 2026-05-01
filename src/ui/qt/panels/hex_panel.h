#pragma once

#include <QWidget>
#include "hex_view.h"

class HexPanel : public QWidget {
    Q_OBJECT
public:
    explicit HexPanel(QWidget* parent = nullptr);
    HexView* view() const { return m_view; }
private:
    HexView* m_view = nullptr;
};
