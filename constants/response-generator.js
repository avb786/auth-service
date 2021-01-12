const responseGenerator = (res, data, status = 200, message, error) => {
    const response = {}
    response.data = data
    response.status = status
    response.message = message
    response.error = error
    res.status(status).json(response)
}

module.exports = {
    responseGenerator
}