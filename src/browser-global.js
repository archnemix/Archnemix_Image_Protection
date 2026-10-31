/** Browser-global entry: exposes the Archx API as `window.Archx` for
 * classic <script> tags (the dist/archx.min.js build target). */
import Archx from './archx.js';
globalThis.Archx = Archx;
export default Archx;
