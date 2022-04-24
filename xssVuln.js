function example30 () {
    // ruleid: jwt-exposed-credentials
    const jose = require('jose')
    const { JWK, JWT } = jose
    const token1 = JWT.sign({password: 123}, 'secret', {some: 'params'})
}
