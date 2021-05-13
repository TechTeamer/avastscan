/* eslint-disable no-console */
const Avast = require('../src/Avast')

const avast = new Avast('/var/run/avast/scan.sock', 30000, console);

(async () => {
  console.log(await avast.getInfo())
  console.log(await avast.scanFile('../package.json'))

  avast.close()
})()
