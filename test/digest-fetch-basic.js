process.env.NO_DEPRECATION = 'digest-fetch';
import chai from "chai";
import chaiHttp from "chai-http";
import factory from "./test-server.js";
import DigestFetch from "../dist/main.js";

const expect = chai.expect;
chai.use(chaiHttp);
chai.should();
const app = factory.getApp();

describe("digest-fetch-basic", function () {
  it("Test Basic Authentication", function () {
    var client = new DigestFetch("test", "test", { basic: true });
    const auth = client.addBasicAuth().headers.Authorization;
    return chai
      .request(app)
      .get("/basic")
      .set("Authorization", auth)
      .then((res) => {
        expect(res).to.have.status(200);
      });
  });
  it("Test Basic Authentication with wrong credential", function () {
    var client = new DigestFetch("test", "test-null", { basic: true });
    const auth = client.addBasicAuth().headers.Authorization;
    return chai
      .request(app)
      .get("/basic")
      .set("Authorization", auth)
      .then((res) => {
        expect(res).to.have.status(401);
      });
  });
});
