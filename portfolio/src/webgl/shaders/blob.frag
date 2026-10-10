uniform float uTime;
uniform vec3 uColorA;
uniform vec3 uColorB;
uniform vec3 uColorC;

varying vec3 vNormal;
varying vec3 vViewPosition;
varying float vDisplacement;

void main() {
  vec3 normal = normalize(vNormal);
  vec3 viewDirection = normalize(vViewPosition);
  float facing = clamp(dot(normal, viewDirection), 0.0, 1.0);
  float fresnel = pow(1.0 - facing, 2.4);

  // Iridescent bands driven by the displacement and viewing angle.
  float bands = 0.5 + 0.5 * sin(vDisplacement * 18.0 + fresnel * 5.0 - uTime * 0.6);
  vec3 base = mix(uColorA, uColorB, smoothstep(-0.12, 0.18, vDisplacement));
  vec3 color = mix(base, uColorC, fresnel * bands);

  vec3 lightDirection = normalize(vec3(-0.5, 0.8, 0.6));
  float diffuse = clamp(dot(normal, lightDirection), 0.0, 1.0);
  vec3 halfway = normalize(lightDirection + viewDirection);
  float specular = pow(max(dot(normal, halfway), 0.0), 64.0);

  color *= 0.45 + 0.7 * diffuse;
  color += specular * 0.5;
  color += fresnel * uColorC * 0.35;

  gl_FragColor = vec4(color, 1.0);

  #include <colorspace_fragment>
}
