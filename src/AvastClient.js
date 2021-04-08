const axios = require('axios')

class AvastClient {
  constructor(baseURL) {
    this.api = axios.create({
      baseURL,
      timeout: 10000
    })
  }

  // Accepts buffer or base64 string
  async scanFile(file) {
    if (Buffer.isBuffer(file)) {
      const response = await this.api.post('/scan', { file: file.toString('base64') })
      return response.data
    }

    throw new Error('AvastClient#scanFile requires buffer as input')
  }
}

module.exports = AvastClient
