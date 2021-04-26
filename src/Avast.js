const net = require('net')
const { promisify } = require('util');
const exec = promisify(require('child_process').exec)

const defaultSockFile = '/var/run/avast/scan.sock'

const awaitMs = async (ms) => {
  return new Promise((res) => {
    setTimeout(res, ms)
  })
}

class Avast {
  constructor (sockFile = defaultSockFile) {
    this.client = null
    this.sockFile = sockFile
    this.resultMap = new Map()
  }

  connect() {
    const client = net.createConnection(this.sockFile)

    client.on('connect', () => {
      this.client = client
    })

    client.on('error', data => {
      console.error('Server error: ', data)
    })

    client.on('data', data => {
      const lines = data.toString().split(/\r\n/gm)
      for (const line of lines) {
        if (line.startsWith('SCAN')) {
          const args = line.split(/\t/gm)

          const fileName = args[0].split(' ')[1]
          // This is used for archives
          const rootFileName = fileName.split('|>')[0]

          if (args.length > 2) {
            // Is the file not excluded?
            if (args[1].startsWith('[E]')) {
              if (!this.resultMap.has(rootFileName)) {
                this.resultMap.set(rootFileName, { is_infected: false, is_excluded: true })
              }
            } else {
              const malware_name = args[args.length-1].replace(/\\/g,'')
              this.resultMap.set(rootFileName, { is_infected: true, malware_name })
            }
          } else {
            if (!this.resultMap.has(rootFileName)) {
              this.resultMap.set(rootFileName, { is_infected: false, is_excluded: false })
            }
          }
        }
      }
    })
  }

  async scanFile(filePath) {
    if (!this.client) {
      await this.connect(this.sockFile)
    }

    const command = `scan ${filePath}\n`

    this.client.write(command)

    return this._getScanResult(filePath)
  }

  async getInfo() {
    if (!this.client) {
      await this.connect(this.sockFile)
    }

    const version = await exec('scan -v')
    const vps = await exec('scan -V')

    return {
      version: version.stdout.trim(),
      virusDefinitionsVersion: vps.stdout.trim()
    }
  }

  async _getScanResult(filePath) {
    await awaitMs(300)
    let scanResult = null

    while(!scanResult) {
      if (this.resultMap.has(filePath)) {
        scanResult = this.resultMap.get(filePath)
      } else {
        await awaitMs(300)
      }
    }

    this.resultMap.delete(filePath)
    return scanResult
  }
}

module.exports = Avast
