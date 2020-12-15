import Strategy from "passport-strategy"
import got from "got"
import url from "url"
import parser from "fast-xml-parser"

import orgDetails from "./orgcode.js"
class SSOUIStrategy extends Strategy {
    constructor(partialOptions, verify) {
        if (!verify) {
            throw new Error("SSO UI Strategy requires a verify function!")
        }

        super()

        const options = {
            casURL: "https://sso.ui.ac.id/cas2/",
            serviceURL: "http://localhost:3000",
            passReqToCallback: false,
            ...partialOptions,
        }

        this.name = "sso-ui"

        this.casURL = options.casURL
        this.serviceURL = options.serviceURL
        this._verify = verify
        this._passReqToCallback = options.passReqToCallback
    }

    async validateTicket(req) {
        const cb = (err, user, info) => {
            if (err) return this.error(err)
            if (!user) return this.fail(info)
            return this.success(user, info)
        }
        try {
            const response = await got(
                new URL("./serviceValidate", this.casURL),
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

            const serviceResponse = parsed["serviceResponse"]

            if (serviceResponse["authenticationFailure"]) {
                return this.fail(new Error("Authentication failed!"))
            }

            const { user: ssoUsername, attributes: attr } = serviceResponse[
                "authenticationSuccess"
            ]

            const user = {
                ssoUsername: ssoUsername,
                name: attr.nama,
            }

            if (attr.peran_user == "mahasiswa") {
                user.institution = `${orgDetails[attr.kd_org]?.major || ""} UI`
                user.npm = attr.npm
            } else if (attr.peran_user == "staff") {
                user.institution = "Staff UI"
                user.npm = attr.nip
            } else {
                user.institution = "UI"
            }

            return this._passReqToCallback
                ? this._verify(req, user, cb)
                : this._verify(user, cb)
        } catch (error) {
            this.fail(error)
        }
    }

    async authenticate(req) {
        const ticket = req.query["ticket"]
        if (!ticket) {
            const redirectURL = url.format({
                pathname: this.casURL,
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
