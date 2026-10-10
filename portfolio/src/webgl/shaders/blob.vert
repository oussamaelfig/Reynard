uniform float uTime;
uniform float uAmplitude;
uniform float uFrequency;
uniform float uReveal;
uniform float uScroll;
uniform vec2 uPointer;

varying vec3 vNormal;
varying vec3 vViewPosition;
varying float vDisplacement;

#include ./noise.glsl

float displacement(vec3 direction) {
  float time = uTime * 0.16;
  float shape = fbm(direction * uFrequency + vec3(time, time * 0.7, -time * 0.5)) - 0.47;
  float ripple = sin(direction.y * 7.0 + uTime * 0.9) * 0.025;

  // Bulge toward the pointer in world space, independent of the mesh rotation.
  vec3 worldDirection = normalize(mat3(modelMatrix) * direction);
  vec3 pointerDirection = normalize(vec3(uPointer * 0.9, 1.0));
  float pull = pow(max(dot(worldDirection, pointerDirection), 0.0), 8.0) * 0.16;

  float amplitude = uAmplitude * (1.0 + uScroll * 1.2);
  return (shape * amplitude + ripple + pull) * uReveal;
}

vec3 displacedPoint(vec3 direction) {
  return direction * (1.0 + displacement(direction));
}

void main() {
  vec3 direction = normalize(position);
  vec3 helper = abs(direction.y) > 0.99 ? vec3(1.0, 0.0, 0.0) : vec3(0.0, 1.0, 0.0);
  vec3 tangent = normalize(cross(direction, helper));
  vec3 bitangent = normalize(cross(direction, tangent));

  // Recompute the normal from two displaced neighbours.
  float offset = 0.01;
  float amount = displacement(direction);
  vec3 point = direction * (1.0 + amount);
  vec3 neighbourT = displacedPoint(normalize(direction + tangent * offset));
  vec3 neighbourB = displacedPoint(normalize(direction + bitangent * offset));
  vec3 displacedNormal = normalize(cross(neighbourT - point, neighbourB - point));
  if (dot(displacedNormal, direction) < 0.0) displacedNormal = -displacedNormal;

  vec4 viewPosition = modelViewMatrix * vec4(point, 1.0);

  vNormal = normalize(normalMatrix * displacedNormal);
  vViewPosition = -viewPosition.xyz;
  vDisplacement = amount;

  gl_Position = projectionMatrix * viewPosition;
}
