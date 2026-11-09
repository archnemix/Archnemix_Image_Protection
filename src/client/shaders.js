/** WebGL2 shader sources kept separate from the viewer lifecycle/state machine. */
export const VERTEX_SHADER = `#version 300 es
      layout(location=0) in vec2 p; out vec2 vUv;
      void main(){ vUv = p*0.5+0.5; vUv.y = 1.0-vUv.y; gl_Position = vec4(p,0.,1.); }`;
export const FRAGMENT_SHADER = `#version 300 es
      precision highp float;
      uniform sampler2D uTex; uniform sampler2D uMap; uniform sampler2D uWm;
      uniform float uGrid; uniform vec2 uCrop; uniform vec2 uFitScale; uniform vec2 uFitOffset;
      uniform float uScrambled; uniform float uSeed; uniform float uWmOn;
      uniform float uLensOn; uniform float uLensActive; uniform vec2 uLensCenter;
      uniform float uLensRadius; uniform vec2 uResolution; uniform float uLocked;
      uniform float uTemporalOn; uniform float uTemporalSign;
      uniform float uTemporalStrength; uniform float uTemporalBlock;
      uniform float uTemporalPattern; uniform float uTemporalChroma;
      uniform float uTemporalDuty; uniform float uTemporalBias; uniform float uBiasSeed;
      uniform float uInterlaceOn; uniform float uInterlacePhase;
      uniform float uInterlacePhases; uniform float uInterlaceLayout;
      uniform float uInterlaceCell; uniform float uInterlaceAxis;
      uniform float uInterlaceFill; uniform float uInterlaceFillBlock;
      uniform float uInterlaceFillStrength; uniform float uInterlaceHiddenScale;
      uniform float uInterlaceActiveGain; uniform float uInterlaceNoiseStrength;
      uniform float uInterlaceBias;
      in vec2 vUv; out vec4 frag;
      float hash(vec2 q){ return fract(sin(dot(q, vec2(127.1,311.7))+uSeed)*43758.5453); }
      float biasHash(vec2 q){ return fract(sin(dot(q, vec2(269.5,183.3))+uBiasSeed)*43758.5453); }
      vec3 hash3(vec2 q){
        return vec3(hash(q), hash(q+19.19), hash(q+47.47));
      }
      vec2 mapToSource(vec2 imageUv){
        vec2 srcUv = imageUv;
        if(uScrambled>0.5){
          vec2 paddedUv = imageUv * uCrop; // orig->padded space
          vec2 tile = floor(paddedUv*uGrid);
          vec2 local = fract(paddedUv*uGrid);
          vec4 m = texelFetch(uMap, ivec2(tile), 0);
          vec2 srcTile = m.rg*255.0;
          if(m.b>0.5) local.x = 1.0-local.x;
          if(m.a>0.5) local.y = 1.0-local.y;
          srcUv = (srcTile+local)/uGrid;
          // Clamp inside the source tile so filtering never blends across
          // scrambled-tile boundaries -> no seams.
          vec2 texel = 1.0 / vec2(textureSize(uTex, 0));
          srcUv = clamp(srcUv, srcTile/uGrid + texel*0.75, (srcTile+1.0)/uGrid - texel*0.75);
        }
        return srcUv;
      }
      vec4 sampleImage(vec2 imageUv){
        vec2 texSize = vec2(textureSize(uTex, 0));
        vec2 srcUv = mapToSource(imageUv);
        vec2 srcPx = srcUv * texSize;
        float footprint = max(length(dFdx(srcPx)), length(dFdy(srcPx)));
        // At ~1:1, fetch the exact texel instead of bilinear-blending two
        // neighbours; this is the difference between crisp type/edges and mush.
        if(footprint > 0.70 && footprint < 1.45){
          ivec2 p = ivec2(clamp(floor(srcPx), vec2(0.0), texSize - 1.0));
          return texelFetch(uTex, p, 0);
        }
        // When minifying, a small 2x2 supersample around the fragment footprint
        // preserves substantially more detail than one bilinear tap (and, for a
        // scrambled texture, avoids cross-tile mipmap bleeding).
        if(footprint >= 1.45){
          vec2 duvX = dFdx(imageUv);
          vec2 duvY = dFdy(imageUv);
          vec4 sum = vec4(0.0);
          sum += texture(uTex, mapToSource(imageUv - 0.25*duvX - 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv + 0.25*duvX - 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv - 0.25*duvX + 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv + 0.25*duvX + 0.25*duvY));
          return sum * 0.25;
        }
        return texture(uTex, srcUv);
      }
      void main(){
        if(uLocked>0.5){ frag=vec4(0.,0.,0.,1.); return; }
        vec2 uv = vUv*uFitScale + uFitOffset;
        if(uv.x<0.0||uv.x>1.0||uv.y<0.0||uv.y>1.0){ frag=vec4(0.,0.,0.,1.); return; }
        // Pointer lens: outside the trusted-pointer disc we sample a heavily
        // quantised (pixelated) version, so a single screenshot/frame grab
        // only ever contains one small sharp region.
        vec2 effUv = uv;
        float lensOutside = 0.0;
        float lensDistPx = 0.0;
        if(uLensOn>0.5){
          vec2 centerPx = vec2(uLensCenter.x, 1.0-uLensCenter.y) * uResolution;
          lensDistPx = distance(gl_FragCoord.xy, centerPx);
          if(uLensActive<0.5 || lensDistPx > uLensRadius){
            float block = max(uResolution.x, uResolution.y) / 34.0;
            vec2 qxy = (floor(gl_FragCoord.xy / block) + 0.5) * block;
            vec2 qUv = vec2(qxy.x / uResolution.x, 1.0 - qxy.y / uResolution.y);
            effUv = qUv * uFitScale + uFitOffset;
            lensOutside = 1.0;
          }
        }
        vec4 c = sampleImage(effUv);
        c.rgb += (hash(gl_FragCoord.xy)-0.5)*(2.0/255.0); // forensic grain
        if(lensOutside>0.5) c.rgb *= 0.82;
        // Literal temporal interlace: each spatial cell belongs to exactly
        // one phase. Inactive cells retain only the configured fill. This
        // runs before the watermark so attribution is present in every
        // presented phase and in a one-frame capture.
        if(uInterlaceOn>0.5){
          vec2 interlaceCell = floor(gl_FragCoord.xy / max(uInterlaceCell, 1.0));
          float assigned = 0.0;
          if(uInterlaceLayout<0.5){
            assigned = mod(interlaceCell.x + (uInterlacePhases<2.5 ? interlaceCell.y : 2.0*interlaceCell.y), uInterlacePhases);
          } else if(uInterlaceLayout<1.5){
            assigned = mod(uInterlaceAxis>0.5 ? interlaceCell.x : interlaceCell.y, uInterlacePhases);
          } else if(uInterlaceLayout<2.5){
            assigned = min(floor(hash(interlaceCell + 913.7) * uInterlacePhases), uInterlacePhases - 1.0);
          } else {
            assigned = mod(interlaceCell.x + interlaceCell.y, uInterlacePhases);
          }
          // Cycle-zero-mean block bias (noise fill only): without it the
          // per-pixel cycle multiset is {c, c+d1, c+d2} and the temporal
          // median of a short screen recording is exactly c whenever the
          // hidden deltas straddle it (~50% of pixels at 3 phases). A
          // per-24px-block offset b, +b*(P-1)/P on the active phase and
          // -b/P hidden, keeps the cycle mean exact while moving every
          // cycle statistic off c. biasHash re-seeds every 90 frames, so
          // longer recordings face a drifting bias, not a fixed offset.
          float iBias = 0.0;
          if(uInterlaceFill>2.5 && uInterlaceFill<3.5){
            vec2 biasCell = floor(gl_FragCoord.xy / 24.0);
            iBias = (biasHash(biasCell) * 2.0 - 1.0) * uInterlaceBias * uInterlaceFillStrength;
          }
          if(abs(assigned-uInterlacePhase)<0.5){
            c.rgb = c.rgb * uInterlaceActiveGain + vec3(iBias * (uInterlacePhases - 1.0) / max(uInterlacePhases, 1.0));
          } else {
            vec3 fillColor = c.rgb;
            if(uInterlaceFill<0.5){
              vec2 qxy = (floor(gl_FragCoord.xy / max(uInterlaceFillBlock, 1.0)) + 0.5) * uInterlaceFillBlock;
              vec2 qUv = vec2(qxy.x / uResolution.x, 1.0 - qxy.y / uResolution.y);
              vec2 fillUv = qUv * uFitScale + uFitOffset;
              if(fillUv.x>=0.0 && fillUv.x<=1.0 && fillUv.y>=0.0 && fillUv.y<=1.0){
                fillColor = sampleImage(fillUv).rgb;
              }
            } else if(uInterlaceFill<1.5){
              fillColor = c.rgb * uInterlaceHiddenScale;
            } else if(uInterlaceFill<2.5){
              fillColor = vec3(0.0);
            } else {
              vec3 delta;
              if(uTemporalChroma>0.5){
                float v = hash(interlaceCell) - 0.5;
                delta = vec3(v, -0.62*v, 0.78*v);
              } else {
                delta = hash3(interlaceCell) - 0.5;
              }
              fillColor = c.rgb + delta * uInterlaceNoiseStrength * uTemporalSign - vec3(iBias / max(uInterlacePhases, 1.0) / max(uInterlaceFillStrength, 0.02));
            }
            c.rgb = mix(c.rgb, fillColor, uInterlaceFillStrength);
          }
        }
        if(uWmOn>0.5){
          vec4 wm = texture(uWm, vUv);
          c.rgb = mix(c.rgb, wm.rgb, wm.a);
        }
        if(uLensOn>0.5 && uLensActive>0.5 && abs(lensDistPx-uLensRadius)<1.5){
          c.rgb = mix(c.rgb, vec3(1.0), 0.35);
        }
        // Temporal shield: complementary per-block noise flips sign every
        // presented frame. The eye integrates the pair toward the image;
        // one screenshot/extension capture keeps a single noisy frame.
        if(uTemporalOn>0.5){
          vec2 blockCell = floor(gl_FragCoord.xy / max(uTemporalBlock, 1.0));
          vec3 delta;
          if(uTemporalPattern>1.5){
            // Horizontal bands interact strongly with rolling-shutter rows.
            float v = hash(vec2(0.0, blockCell.y)) - 0.5;
            delta = uTemporalChroma>0.5 ? vec3(v, -0.62*v, 0.78*v) : hash3(vec2(0.0, blockCell.y)) - 0.5;
          } else if(uTemporalPattern>0.5){
            float parity = mod(blockCell.x + blockCell.y, 2.0) > 0.5 ? 1.0 : -1.0;
            if(uTemporalChroma>0.5){
              float v = (0.35 + 0.65*hash(blockCell)) * parity;
              delta = vec3(v, -0.62*v, 0.78*v) * 0.5;
            } else {
              delta = (0.35 + 0.65*hash3(blockCell)) * parity * 0.5;
            }
          } else if(uTemporalChroma>0.5){
            float v = hash(blockCell) - 0.5;
            delta = vec3(v, -0.62*v, 0.78*v);
          } else {
            delta = hash3(blockCell) - 0.5;
          }
          c.rgb += delta * uTemporalStrength * uTemporalSign;
          // Asymmetric duty bias: a slowly-drifting per-block offset b is
          // applied +2b/3 on one frame and -b/3 on the next two. The
          // temporal MEAN the eye integrates is exactly c, but the sample
          // MEDIAN of any short capture converges to c - b/3, not c —
          // median-filter recovery of the active/interlace subsets is
          // permanently biased, and b re-rolls every ~90 frames so even
          // long-window medians keep chasing a moving target.
          vec2 biasCell = floor(gl_FragCoord.xy / 24.0);
          float b = biasHash(biasCell) - 0.5;
          c.rgb += vec3(b) * uTemporalBias * uTemporalDuty;
        }
        frag = vec4(c.rgb, 1.0);
      }`;
