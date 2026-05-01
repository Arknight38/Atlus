#pragma once

#include <QString>
#include <QColor>

namespace Theme {

enum ColorRole {
    Background,
    BackgroundSecondary,
    BackgroundTertiary,
    Foreground,
    Border,
    Selection,
    Accent,
    AlternateRow,
    HexAltRow,
    HexOffset,
    HexText,
    HexCursor,
    HexSelection,
    HexDiff,
    Keyword,
    Type,
    String,
    Number,
    Comment,
    Error,
    ScrollBar,
    ScrollBarHover,
};

QColor color(ColorRole role);
QString stylesheet();
void applyToApplication();

} // namespace Theme
