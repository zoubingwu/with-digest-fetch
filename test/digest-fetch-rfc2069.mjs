process.env.NO_DEPRECATION = "digest-fetch";

import chai from "chai";
import chaiHttp from "chai-http";
import DigestFetch from "../dist/index.mjs";
import factory from "./test-server.mjs";

const expect = chai.expect;
chai.use(chaiHttp);
chai.should();
const app = factory.getApp();

describe("digest-fetch-rfc2069", function () {
  it("Test RFC2069", function () {
    const client = new DigestFetch("test", "test");
    return chai
      .request(app)
      .get("/auth")
      .then((res) => {
        expect(res).to.have.status(401);
        client.lastAuth = res.res.headers["www-authenticate"];
      })
      .then(() => {
        client.parseAuth(client.lastAuth);
        const auth = client.addAuth("/auth", { method: "GET" }).headers
          .Authorization;
        return chai
          .request(app)
          .get("/auth")
          .set("Authorization", auth)
          .then((res) => {
            expect(res).to.have.status(200);
          });
      });
  });

  it("Test RFC2069 with wrong credential", function () {
    var client = new DigestFetch("test", "test-null");
    return chai
      .request(app)
      .get("/auth")
      .then((res) => {
        res.should.have.status(401);
        client.lastAuth = res.res.headers["www-authenticate"];
      })
      .then(() => {
        client.parseAuth(client.lastAuth);
        const auth = client.addAuth("/auth", { method: "GET" }).headers
          .Authorization;
        return chai
          .request(app)
          .get("/auth")
          .set("Authorization", auth)
          .then((res) => {
            expect(res).to.have.status(401);
          });
      });
  });
});
