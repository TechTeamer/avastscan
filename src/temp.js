const fs = require("fs").promises
const os = require("os")
const path = require("path")

const withTempFile = (fn) => withTempDir((dir) => fn(path.join(dir, "file")))

const withTempDir = async (fn) => {
  const dir = await fs.mkdtemp(await fs.realpath(os.tmpdir()) + path.sep)
  try {
    return await fn(dir)
  } finally {
    fs.rmdir(dir, {recursive: true})
  }
};

module.exports = {
  withTempFile,
  withTempDir
}
