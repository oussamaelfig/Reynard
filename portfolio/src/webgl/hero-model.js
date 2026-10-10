import * as THREE from 'three'
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js'
import { MeshoptDecoder } from 'three/addons/libs/meshopt_decoder.module.js'
import { DRACO_GLTF_CONFIG, DRACOLoader } from 'three/addons/loaders/DRACOLoader.js'
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js'
import { KTX2Loader } from 'three/addons/loaders/KTX2Loader.js'

const TARGET_SIZE = 2.4

// Loaded on demand (dynamic import) only when site.heroModelUrl is set.
// The Draco and Basis decoders are emitted by Vite from three's own package.
export async function loadHeroModel(url, renderer, scene, onProgress = () => {}) {
  const draco = new DRACOLoader().setDecoderPath(DRACO_GLTF_CONFIG)
  const ktx2 = new KTX2Loader().detectSupport(renderer)
  const loader = new GLTFLoader()
    .setDRACOLoader(draco)
    .setKTX2Loader(ktx2)
    .setMeshoptDecoder(MeshoptDecoder)

  try {
    const gltf = await loader.loadAsync(url, (event) => {
      if (event.total) onProgress((event.loaded / event.total) * 0.9)
    })

    const pmrem = new THREE.PMREMGenerator(renderer)
    scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture
    pmrem.dispose()

    const model = gltf.scene
    const bounds = new THREE.Box3().setFromObject(model)
    const size = bounds.getSize(new THREE.Vector3())
    model.position.sub(bounds.getCenter(new THREE.Vector3()))

    const wrapper = new THREE.Group()
    wrapper.add(model)
    wrapper.scale.setScalar(TARGET_SIZE / Math.max(size.x, size.y, size.z))

    return wrapper
  } finally {
    draco.dispose()
    ktx2.dispose()
  }
}
