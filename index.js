import Strategy from "passport-strategy"
import got from "got"
import url from "url"
import parser from "fast-xml-parser"

class SSOUIStrategy extends Strategy {
    constructor(partialOptions, verify) {
        if (!verify) {
            throw new Error("SSO UI Strategy requires a verify function!")
        }

        const options = {
            casURL: "https://sso.ui.ac.id/cas2/",
            serviceURL: "http://localhost:3000",
            ...partialOptions,
        }

        this.casURL = options.casURL
        this.serviceURL = options.serviceURL
        this._verify = verify
    }

    async validateTicket(req) {
        const cb = (err, user, info) => {
            if (err) return self.error(err)
            if (!user) return self.fail(info)
            return self.success(user, info)
        }
        try {
            const response = await got(
                new URL("./serviceValidate", this.options.casURL),
                {
                    searchParams: {
                        service: this.serviceURL + url.parse(req.url).pathname,
                        ticket: req.query.ticket,
                    },
                }
            )

            const parsed = parser.parse(response.body, {
                ignoreNameSpace: true,
            })

            const response = parsed["serviceResponse"]

            if (response["authenticationFailure"]) {
                return this.fail(new Error("Authentication failed!"))
            }

            const profile = parsed["serviceResponse"]["authenticationSuccess"]

            return self._verify(profile, cb)
        } catch (error) {
            this.fail(error)
        }
    }

    async authenticate(req) {
        const ticket = req.param("ticket")
        if (!ticket) {
            const redirectURL = url.format({
                pathname: this.options.loginURL,
                query: {
                    service: this.serviceURL + url.parse(req.url).pathname,
                },
            })

            return this.redirect(redirectURL)
        }

        return await this.validateTicket(req)
    }
}

export default SSOUIStrategy
