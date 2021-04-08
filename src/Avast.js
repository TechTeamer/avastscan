const net = require('net')

const defaultSockFile = '/var/run/avast/scan.sock'

const awaitMs = async (ms) => {
  return new Promise((res) => {
    setTimeout(res, ms)
  })
}

class Avast {
  constructor () {
    this.client = null
    this.resultMap = new Map()
  }

  connect(sockFile = defaultSockFile) {
    const client = net.createConnection(sockFile)

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
      throw new Error('Client not connected')
    }

    const command = `scan ${filePath}\n`

    this.client.write(command)

    return this._getScanResult(filePath)
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

    return scanResult
  }
}

module.exports = Avast
