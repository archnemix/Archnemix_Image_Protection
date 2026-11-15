/* Technical page orchestrator */
import { initSharedUi } from '../shared/ui.js';
import { initAtlas } from './atlas.js';
import { initFlowWidget } from './flow-widget.js';
import { initPlanWidget } from './plan-widget.js';
import { initTokenWidget } from './token-widget.js';
import { initSaturationWidget } from './saturation-widget.js';
import { initBchWidget } from './bch-widget.js';
import { initSurvivalWidget } from './survival-widget.js';

initSharedUi();
initAtlas();
initFlowWidget();
initPlanWidget();
initTokenWidget();
initSaturationWidget();
initBchWidget();
initSurvivalWidget();
