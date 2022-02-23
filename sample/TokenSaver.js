const {Client} = require('pg')
const {v4: uuidv4} = require('uuid');

module.exports = class TokenSaver {
    async saveAuthToken(tokenData, yardId) {
        console.log('saving auth token')

        const client = new Client()
        await client.connect()

        const query = `INSERT INTO erp_tool_credentials
                       (qb_company_id, qb_access_token, qb_refresh_token, qb_expires_in,
                        qb_refresh_token_expires_in, qb_created_at, yard_id)
                       VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7) RETURNING *`
        const values = [tokenData.realmId, tokenData.access_token, tokenData.refresh_token, tokenData.expires_in, tokenData.x_refresh_token_expires_in, tokenData.createdAt/1000, yardId]

        try {
            const res = await client.query(query, values)
            console.log('saved credentials')
            console.log(res.rows[0])
        } catch (err) {
            console.log(err.stack)
        }
        await client.end()
    }
}
