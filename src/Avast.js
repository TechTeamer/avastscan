const net = require('net')
const fs = require('fs').promises
const path = require('path')
const async = require('async')

const awaitMs = async (ms) => {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

class Avast {
  constructor (sockFile = '/var/run/avast/scan.sock', timeoutMs = 30000, logger = null) {
    this.client = null
    this.sockFile = sockFile
    this.resultMap = new Map()
    this.timeoutMs = timeoutMs
    this.logger = logger
    this.avastInfo = null
    this.history = []

    this.queue = async.queue(async (task) => {
      return await this._scanFile(task.filePath)
    }, 1)
  }

  async connect (reconnect = false) {
    if (this.client && !reconnect) {
      return Promise.resolve()
    }

    return new Promise((resolve, reject) => {
      this.close()

      this.client = net.createConnection(this.sockFile)
      this.client.setTimeout(1000 + this.timeoutMs)

      this.client.on('ready', () => {
        this.client.on('data', this._processData.bind(this))
        resolve()
      })

      this.client.on('timeout', () => {
        this.client.destroy() // => will emit 'close'
        reject(new Error('avastscan timeout'))
      })

      this.client.on('end', () => { // https://nodejs.org/api/net.html#net_event_end
        this.client.end() // TODO: will emit 'close' ????
      })

      // TODO
      this.client.on('error', err => { // after this will emit 'close'
        if (this.logger) {
          this.logger.error(err)
        }
      })

      this.client.on('close', () => {
        this.client.removeAllListeners()
        this.client = null
      })
    })
  }

  async close () {
    if (this.client) {
      this.client.destroy()
    }
  }

  async getInfo () {
    await this.connect()

    this.client.write('VPS\n')

    const timeout = Date.now() + this.timeoutMs
    while (Date.now() <= timeout) {
      await awaitMs(100)
      if (this.avastInfo) {
        break
      }
    }

    return this.avastInfo
  }

  async scanFile (filePath) {
    await this.connect()

    return new Promise((resolve, reject) => {
      this.queue.push({ filePath }, (err, result) => {
        if (err) {
          reject(err)
          return
        }
        resolve(result)
      })
    })
  }

  async _scanFile (filePath) {
    const resolvedFilePath = path.resolve(filePath)

    // Confirm that file exists
    await fs.stat(resolvedFilePath)

    // reset everything
    this.history = []

    const command = `SCAN ${resolvedFilePath}\n`

    this.client.write(command)

    const timeout = Date.now() + this.timeoutMs
    while (Date.now() <= timeout) {
      await awaitMs(100)
      if (this.resultMap.has(resolvedFilePath)) {
        break
      }
    }

    const scanResult = this.resultMap.get(resolvedFilePath)
    this.resultMap.delete(resolvedFilePath)

    if (!scanResult) {
      throw new Error('Scan Result Timeout')
    }

    if (scanResult.error) {
      throw scanResult.Error
    }

    const isSafe = !scanResult.is_infected && !scanResult.is_password_protected && !scanResult.permission_denied
    return {
      history: [...this.history],
      is_safe: isSafe,
      ...scanResult
    }
  }

  async _processData (data) {
    const lines = data.toString().split(/\r\n/gm)
    for (const line of lines) {
      // Engine Error (451 Engine Error) <- message
      if (line.startsWith('451')) {
        const args = line.split(/\t/gm)
        const fileName = args[0].split(' ')[1]
        const rootFileName =  fileName.split('|>')[0]
        this.logger.error('Engine error', line)
        this.resultMap.set(rootFileName, { error: true, Error: new Error('Engine error') })
        return
      }

      if (line.startsWith('VPS')) {
        this.avastInfo = line.replace('VPS ', '').trim()
      }

      if (line.startsWith('SCAN')) {
        const args = line.split(/\t/gm)
        const fileName = args[0].split(' ')[1]
        // This is used for archives
        const rootFileName =  fileName.split('|>')[0]
        this.history.push(line)

        if (!this.resultMap.get(rootFileName)) {
          this.resultMap.set(rootFileName, { is_infected: false, is_excluded: false, is_password_protected: false, malware_names: [] })
        }

        if (args.length > 2) {
          // Is the file not excluded?
          const result = this.resultMap.get(rootFileName)
          if (args[1].startsWith('[E]')) {
            if (line.includes('Archive\\ is\\ password\\ protected')) {
              result.is_password_protected = true
            } else if (line.includes('Permission\\ denied')) {
              result.permission_denied = true
            } else {
              result.is_excluded = true
            }
          } else {
            const malwareName = args[args.length - 1].replace(/\\/g, '')
            result.is_infected = true
            result.malware_names.push(malwareName)
          }
        }
      }
    }
  }
}

module.exports = Avast
