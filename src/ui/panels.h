#pragma once

#include "gui_state.h"

// Panel drawing functions
void DrawFunctionsPanel();
void DrawSectionsPanel();
void DrawImportsPanel();
void DrawHexPanel();
void DrawDisasmPanel();
void DrawAobPanel();
void DrawLogPanel();
void DrawPseudocodePanel();
void DrawSettingsModal();

// Disassembly panel cache management (called by ResetSessionAfterLoad)
void ResetDisasmPanelCaches();
