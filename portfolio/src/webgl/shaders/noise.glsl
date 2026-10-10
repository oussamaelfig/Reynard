// Hash-based 3D value noise with quintic interpolation, layered into fbm.

float hash(vec3 p) {
  p = fract(p * vec3(443.897, 441.423, 437.195));
  p += dot(p, p.yzx + 19.19);
  return fract((p.x + p.y) * p.z);
}

float valueNoise(vec3 p) {
  vec3 cell = floor(p);
  vec3 local = fract(p);
  vec3 blend = local * local * local * (local * (local * 6.0 - 15.0) + 10.0);

  float n000 = hash(cell);
  float n100 = hash(cell + vec3(1.0, 0.0, 0.0));
  float n010 = hash(cell + vec3(0.0, 1.0, 0.0));
  float n110 = hash(cell + vec3(1.0, 1.0, 0.0));
  float n001 = hash(cell + vec3(0.0, 0.0, 1.0));
  float n101 = hash(cell + vec3(1.0, 0.0, 1.0));
  float n011 = hash(cell + vec3(0.0, 1.0, 1.0));
  float n111 = hash(cell + vec3(1.0, 1.0, 1.0));

  float x00 = mix(n000, n100, blend.x);
  float x10 = mix(n010, n110, blend.x);
  float x01 = mix(n001, n101, blend.x);
  float x11 = mix(n011, n111, blend.x);

  return mix(mix(x00, x10, blend.y), mix(x01, x11, blend.y), blend.z);
}

float fbm(vec3 p) {
  float sum = 0.0;
  float amplitude = 0.5;

  for (int octave = 0; octave < 4; octave++) {
    sum += valueNoise(p) * amplitude;
    p = p * 2.03 + vec3(17.1, 9.2, 4.7);
    amplitude *= 0.5;
  }

  return sum;
}
