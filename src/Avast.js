const net = require('net')
const { promisify } = require('util')
const exec = promisify(require('child_process').exec)
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

    this.queue = async.queue(async (task, callback) => {
      try {
        await callback(null, this.scanFile(task.filePath))
      } catch (err) {
        if (this.logger) {
          this.logger.error(err)
        }
        callback(err)
      }
    }, 1)
  }

  async connect (reconnect = false) {
    if (this.client && !reconnect) {
      return Promise.resolve()
    }

    return new Promise((resolve, reject) => {
      if (this.client) {
        this.client.destroy()
      }

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

  async getInfo () {
    if (!this.client) {
      await this.connect()
    }

    const version = await exec('scan -v')
    const vps = await exec('scan -V')

    return {
      version: version.stdout.trim(),
      virusDefinitionsVersion: vps.stdout.trim()
    }
  }

  async scanFile (filePath) {
    return await this.queue.push({ filePath })
  }

  async _scanFile (filePath) {
    const normalizedFilePath = path.normalize(filePath)

    // Confirm that file exists
    await fs.stat(normalizedFilePath)

    if (!this.client) {
      await this.connect()
    }

    const command = `scan ${normalizedFilePath}\n`

    this.client.write(command)

    const timeout = Date.now() + this.timeoutMs

    while (Date.now() <= timeout) {
      await awaitMs(300)
      if (this.resultMap.has(normalizedFilePath)) {
        break
      }
    }

    const scanResult = this.resultMap.get(normalizedFilePath)
    this.resultMap.delete(normalizedFilePath)

    if (!scanResult) {
      throw new Error('Scan Result Timeout')
    }

    return scanResult
  }

  async _processData (data) {
    const lines = data.toString().split(/\r\n/gm)
    for (const line of lines) {
      if (line.trim() === '200 SCAN OK') {
        // do nothing
      }

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
            const malwareName = args[args.length - 1].replace(/\\/g, '')
            this.resultMap.set(rootFileName, { is_infected: true, malware_name: malwareName })
          }
        } else {
          if (!this.resultMap.has(rootFileName)) {
            this.resultMap.set(rootFileName, { is_infected: false, is_excluded: false })
          }
        }
      }
    }
  }
}

module.exports = Avast
