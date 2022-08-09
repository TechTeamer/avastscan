const FormData = require('form-data')

class AvastClient {
  constructor (options) {
    const { baseURL, timeout = 30000 } = options || {}

    if (!baseURL) {
      throw new Error('BaseURL not provided')
    }

    this.baseURL = baseURL
    this.timeout = timeout
  }

  // Accepts fileStreams or buffers
  async scanFile (file) {
    const formData = new FormData()
    formData.append('file', file)
    const response = await fetch(`${this.baseURL}/scan`, { method: 'POST', body: formData, timeout: this.timeout })
    return response.json()
  }

  async getInfo () {
    const response = await fetch(`${this.baseURL}/info`, { method: 'GET', timeout: this.timeout })
    return response.json()
  }
}

module.exports = AvastClient
