use crate::{ModulusSignatureVerifier, ModulusVerifyError, PROTON_SRP_VERSION};

use super::*;
use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};

struct TestNoOpVerifier {}

impl ModulusSignatureVerifier for TestNoOpVerifier {
    fn verify_and_extract_modulus(
        &self,
        modulus: &str,
        _server_key: &str,
    ) -> Result<String, ModulusVerifyError> {
        Ok(modulus.to_string())
    }
}

struct SrpInstance {
    //These are provided data. Username is not used, but helps understanding which test case we're referring to.
    version: u8,
    _username: &'static str,
    password: &'static str,
    modulus: &'static str,
    salt: &'static str,
    server_ephemeral: &'static str,
    client_secret: &'static str,
    expected_client_ephemeral: &'static str,
    expected_client_proof: &'static str,
    expected_server_proof: &'static str,
}

const PYTHON_SRP_INSTANCES: &[SrpInstance] = &[
    SrpInstance {
        version: 4,
        _username: "test",
        password: "test",
        modulus: "G2TfKd7dhlYkXbfu51FEKtnPHa/FpxqUB2OFwvv5+nrWPpTLNl7JTrpb4THPY9OTDKxHVd5tBiXCTdmpBlUdIWYBIi66lP9Qx4uLJtvydjb0AZ8XALoJEodGLP+tT4iyLWa7+JkwkIZeRtB37PHbeMsqsNA2rXhrBGtdk71HPJV3mRTLk/YH/X77nTQWGVEmPOeUvxgfswHuRE0XCZnq/5QnzEFRvZGnVfGhhACcFBixbux7/C1fiNQrOKTMF2tz6rEy/jfdfhFi3KHRPoGm8Q8JDed+uMxJLNCxm7b8FR9bStVrFDCNWC2GRxOQxCI0AK7j1elMlz+5l9Wfip8wnw==",
        salt: "Jl54BOeNTVl8Ng==",
        server_ephemeral: "ycjIyRFPVgILQUczPERQnD0txE5jmJEIjXZa3G6lIDi6XELRuQtHIHVCOQ2iUHg4EaeSHvcXqa29o50n6mR1wZ6P9zduWG3ww2ThxTMvWvLlI4s3lzZVXlL+ncaEk3D6okjb1qHszAP+pm2ZdxUhHSCZE5IHHWTCXwlxOaxvNuYzpCTyW/DK1XgRM8ysrWHC/JLhFpTW/CfBQi0d0XRWmVb+1SvdSHR4MOj24FQLrNA0hbayRYEp7wQbL7Ts+I8lOB/w7E8KiYe2+DXcUdTozGdMPGOsf9n/w7ZULtXXH03a7hfl74sZ4caCbk0RBswq4Mj8y5kpMGXadnby5oHShQ==",
        client_secret: "eOu9ioj1jqrnee1w1HJ8Op9L7LLcCtME40q2HEAAhu4=", 
        expected_client_ephemeral: "1HLx1rlk4H/0no233yNKLxdcPd+IfvyLF1c6R5ZzCFOKy8XprU1APUWpm9Q+A5hu5HlSaVlcUBj1xS3TNT487OAa2bvCS0ryDfTOax2ZtVGGQ4i+O5e5OgO6MV7ORx97DpwzU4N6t6D9hdUByeH0yWAXe+6OVLPcouMu0x487qDvIbivXJVqMzaP8yGMTGeZWwj+03d4ShPzXQEdAADqDWJcs9ktQOUE1feioN3c6eGTeMhUf2RKDjS8GtEqj927Hk8wBPAIlWWd0S3rCibuimpU3giDxy/cHOHFoT35yS1DFYoQNytqwZelcdCi+tcUznlbO7HD3tl+M9nlqpeLjg==",
        expected_client_proof: "+7Ocq5542c9zfVWMSkXeG/I7mcz5DIrg0dMu7NmraD6J7+2zyBWqIjlc4Ej+ZiP7CNUBjTeEvjwZ+xLIMsJorbOWhjkyq9S4PkARw1b8IsIajfloUV9vlLqmxP9bKrJ7Xk6KQ9pMziqf4qA1O6dW55s7H3Git4zKZlxQLjW/sQnABaYtyfzGgCC2hQUIYJiAH1tZVNezcyYtUHICpFUwj3t4afw0+pbunIdDjuf1YOWixreupLfLgml1IMXBm7fkZYIrnnO5aEskrprRJpJDg2iSSqhxguOnsHbnC+wVjXDZtap7Am8mRh4b/Hv0iWCqCkTf1YeHqYJCuqcbmVCw+A==",
        expected_server_proof: "D9Oj+Qiju2+H/xqGwpDXa4ceSogtyo4sBgKoirTHnIJSL8jRZL+dNqvhG1FuiOlMk9K75tfS7umBLCGAyTC1RsNS5vDE1U3Vrkg29XI4P4q4hjf3NxVq0F/NPrYNcuyJLTSXBHr0T+8d79WmM1UGTQsw/UILuGURDkqouSKFSADIEuv4QYQ21KxcIep+ptLQy/0oio15ciFGC4w6lnT+wLCHp6HoBcteRrz0bnlAfdoSSWZiL91MkYCU7++wV4q8VVp7HwIBNGYvLE9nnGSvOuBMFhsB8HgpxO8EQcVl/plQiZk5/cYQCRsiOP6XqxyDFgQpXPcQwz1FVWd8dycatA==",
      },
      SrpInstance {
        version: 4,
        _username: "LeadingZerosSalt",
        password: "test",
        modulus: "G2TfKd7dhlYkXbfu51FEKtnPHa/FpxqUB2OFwvv5+nrWPpTLNl7JTrpb4THPY9OTDKxHVd5tBiXCTdmpBlUdIWYBIi66lP9Qx4uLJtvydjb0AZ8XALoJEodGLP+tT4iyLWa7+JkwkIZeRtB37PHbeMsqsNA2rXhrBGtdk71HPJV3mRTLk/YH/X77nTQWGVEmPOeUvxgfswHuRE0XCZnq/5QnzEFRvZGnVfGhhACcFBixbux7/C1fiNQrOKTMF2tz6rEy/jfdfhFi3KHRPoGm8Q8JDed+uMxJLNCxm7b8FR9bStVrFDCNWC2GRxOQxCI0AK7j1elMlz+5l9Wfip8wnw==",
        salt: "AA54BOeNTVl8kg==",
        server_ephemeral: "ZxnhUU0PpHLOlmmbf6eM2VKoAf/FE41m5vG4Eh1XxyT1sPm7jsZbTK0HYqm8MXQiXMBHJFjgfg6JSjEczKZWUKhb9a6bd9dngGE4eCpCMPOCaB44Gf5Qwx5FLJ6E8X8EpidZE1+f1+2uEgA1bLtxozKrwPAGERm3xUJVuWynKuYRvZz/V0Vg84ih6Rq/lag/TldXNRGwJeidFLXn5TtYfqvLhVYIuxpc6dJbmwhT40gM5BWw4QlZmNKOaRacRAJgk1OW78e+CFH5u152AOm0e7Cq6Y5ObXW7hTSPg5y1XU57/vRSsO96kUhGi/BDzsLMSzzHgroyBZSUO7UUlzNSaQ==",
        client_secret: "ZcozXCcxfWYBxAErM83vv4G/4l5I/W19hRaOuqPI9tM=", 
        expected_client_ephemeral: "unoWdTFpAR8HcPsDbu7olfsbPJD9EVQ3OnQYivxHqzlY43JQi7x7Mq74grwH3EfVWyJkt7Zpb8Yy+cmErw5rHkvV9EwHtdgmBH0B7T8HYo773WthzIhZGU4eNqrZD7zgmPolGXP4tT1/TvyXsbT2XyqoapdHELIRMK2alE5Eh8obrIBi92+HIRmdxHGaXoNq0HmCQSIDWeR9k7fwMYIDM2zhUUnlEzOYeW1dHczcSc1FXiXfQUYvEPdNrXOAASk71TTLAJ0rAziGd+6TQPGSZSaJRQSMd21p+yqYLw6+IZYtq/VzRI7FXtBDzldSVG2dsmXHPjgKpx5EAUlPYic4Tg==",
        expected_client_proof: "x+BR6EX+m/gOgLlTH+pxhD/zRmku8iKdF7wCB4st9heBcPi47mUnyY+21m+hsXRB4Ygjm6yJgiiUDyioovTvkHchejynUujlhRW1dG3drHf+l8NOAtV19DaAxLNXXN7iPh65P5xfO8lMFznjiS5mFLdtoXgy9U/S0gQ0RTGH7oM0X5QqHlNQml8xFM4JWiwomv9lKaDmpBOgBYzyezTb9W1eWZTohKvEps4Avcht9dlVkFLr6PvlHpNPDt9Fxe3owRLVs79pCBb+MidS1YZvKoefUL3QtAl5mjgR+Aq3l1jyb5bV90hlXNoXHnrtn44785/kO4rqBHvubZAyvblYrg==",
        expected_server_proof: "IPIs2+Z/Yp3ImACf1mHG0T7/4qtXXuUbBcklTJe0zuIImqHaucPheqhD6kdI/qg7NEfypx0ZkWDjg48QnbmxHPMbfh+bRvIwIu+eGEoMG4XzQl7mRnD99VyIBIJKUnzQ0slcbjhQxGFpB5y7d/VAX7ZEoGroAe3+4Tsr/KQl2IbRSTsWLzLv8hlL9/qRS1Wpj9PP4/Yq8THeHSfTMPmvnF9ixiVAn127VwzAV+yThL2ivNAz9NTccWMelJYDiMX4N4TCHdJzugP3R5OgEWTPMMgZM+oYhYWlHud/Dt00SNuWK3P232Gjj6HQB5AwWkHGczlnG807xrXhs5AhIySHdA==",
      },
      SrpInstance {
        version: 4,
        _username: "TrailingZerosSalt",
        password: "test",
        modulus: "G2TfKd7dhlYkXbfu51FEKtnPHa/FpxqUB2OFwvv5+nrWPpTLNl7JTrpb4THPY9OTDKxHVd5tBiXCTdmpBlUdIWYBIi66lP9Qx4uLJtvydjb0AZ8XALoJEodGLP+tT4iyLWa7+JkwkIZeRtB37PHbeMsqsNA2rXhrBGtdk71HPJV3mRTLk/YH/X77nTQWGVEmPOeUvxgfswHuRE0XCZnq/5QnzEFRvZGnVfGhhACcFBixbux7/C1fiNQrOKTMF2tz6rEy/jfdfhFi3KHRPoGm8Q8JDed+uMxJLNCxm7b8FR9bStVrFDCNWC2GRxOQxCI0AK7j1elMlz+5l9Wfip8wnw==",
        salt: "Jl54BOeNTVl8AA==",
        server_ephemeral: "aINP+hDku8hA2WT3Xy1CbVmwntaA1m+0S38TmoDC2b5n7jHPkPVkyy4/C8MinRRxI2/VSEFEyciBAuA+5CXJ7LL1W5XIbn8MXFOcoHdnnJXQpZGlUIeB9POX7wojXOx2AzFEA5eA44Q0gqKqAYLZ6s46P8kDEcqmQnl1k2O5mjvsxKjtX2SqWmK/ik6mJWFVcSY3nIPl4GaujxOH5A9g1Kh4fzIDQzjtAPSubar4HQXjjdeGqj+NORH1oxwf5fhDX10h4FlvleuhwH9/J2weaDpKQO/gg0d2P95R5SEhEXWFbsDbLVEthD9o/Ol2iM6CgGuqE/FbmiI619rpohJYGg==",
        client_secret: "kFbH55RJ7PW2lbf/f6jV7/y3gMTnB04CBH4+VTtpp6k=", 
        expected_client_ephemeral: "8W63FkEDjeJtrfNLuo/4LsLBASbOHKGj2ySHcIwHaDQ6zGwyo6fbmecPdX+PvoXkm5TzY+yzhLGyjD/PUvVQwRYcw2mva0bukCgLNH8U7efHKETB1MlKs1BA6At1LhqLjyxzkvFbdi7KzAAdkXwqiCspJHIO13BIZ7aWUb8tMVyOPKz8S3A982h+UQLJ+/KJmqHWEkBMgeepiMVqPyLBSJIJWyS9x7dTiHYnMyq9wH98VFrolPew0GgF5b4gKFWL91udhFL/nTmNV4kowuZ3JSmDPBjIO45wSilUs6WFPUt0C9WxUrU6nsJeayCMX1/vKAqmWmwKz/Fa9xtL8g4nbQ==",
        expected_client_proof: "H313jRnJnVDOCiq5iDkkKQbep1SF7SVxkz4C74JG8a0uzrf8GIKdtFby4fi0icTGph6xVWG/ferodX1wpky6C0jrn8zLcsaoJwwf+rY5a5yYFTiRokncHpqiTNkm4jKsdWKwJ9bNum2UwIXvy/Dj5PiEEbAF1dPj/zKD3n5nkingCw+m13qgYKZWtYikKdm/L6Z2FIt4xahaZzJ8wy0VwAv+XzTzmI/e/q4UJ1BWxQJayKqosHLJrtfxZ1J88KHNaleio+47gB4BP8dxN38yMLbU4jbniNUgXE6mVUxM9muq2UHbz22wglTeMzHj8RigYXCJKMt4wEGRWbWdt3f1ZA==",
        expected_server_proof: "iNsC4HuEaS0l/rhb4rLIK62qfU3eK6p42f4PMIcP1VaJ09RY99a9U0wenIjWXJwbsYMOFctFqXT7oRRIZK6DrlVU72uJFcVuKLbtPzj+t0IB51hCC+k0RkNgBdbPaZXhvpSJ5UdABPiE8k7XqfoIuKqjTA+W/3BV1LNh24P6OH0Fv3XjJWefvV/aTT/aGOH2hZqpfGpvE0ZlGSdAqRmWWxEFAi4KjRMDYg20NdIXGbSl7HFpJ80ny2e84zfUDRNVZ+Qp5XV0lMmoErdAcO9BPyMEB3alJYBNyU40K+htUV1Ioiyxa3uu2I8ltETkWfajay39qe4FuhGhw0VHwcZLYw==",
      },
      SrpInstance {
        version: 4,
        _username: "abc123",
        password: "LongerPassword",
        modulus: "+2RD2Y2hcERcl5XcNROY8d4VGPsoJ/dX6IBcX0PcKSdJkGCpKRcSRbIPrtTw71YRJ2QwoZQ/b9jnmZ2PQEB0lO4v0UezHswdWax/Y+kmbObuWPqbVNP/P3EvHyEDU+dxRzCnp4fTbXt9CUDxajAmPq1EjAm+HqnzIv6KhEowxLkAdH8wBX8zz4UL1xfQq4AIvm6zM9MPAsFXVgH4B3MH/KbaDb4BVsSF4wNDo3HpCDtY+PV9sEn0aprO4AwacC6Z0EwHd1Q7OiW4szvzXG6VMy4MkH+zV6RqKNsHNRDceQPw4UtbbdEZRfDRm345OdlC6ICNi//ypK415O7OSrBpvQ==",
        salt: "hyzJpo9GoQaQZg==",
        server_ephemeral: "0JXIUjckbsCCUHx/yQ8Yla1fiirsTLhfIPshTpcwiN1BYJZ6F7rTH2F5x8FMf0svQNJB2DakiSIpU0L1EPV4QArNCwyP+6UFDI9qwtlihAj20BZAM3G8w5Ys+iY2ZUUTMhbiHif/xE4E1bUf8jb9HG7Hisk6RB7GW+10n7dq+6WcrhAFVE02CrV2gffFxrz+4hsM5ArZvi3ydgM/vXL75jBJtRASBlyS0uz+F//qbZ7j6gbr+V7w4bhja+idrPC5F3oVVPfPXllyw7tBVlq2FIkhTdbG3mu0+EdvpA4yf5U1E/Ewb+95ouCNXm9nCG9K/ZpjFv17H4BXcDHVQ5Y2Vg==",
        client_secret: "aQrPeTJcYKNFmcymrdqJX8zYAtHCentX3F6kcieREvM=", 
        expected_client_ephemeral: "OjzA7zh65oS+/CsKOWyd+XxMtXCgizkciQ8s1BGDKLWU4pDsoEe2QQGIVCJXY4WMu2meRxIjRVDwTWDj1IGA3jBh60PC+3EfmJclnw+jsB3Jxr3Xg7R/MTkh0Ib6F+pkXiyDw3tzVSmXA+G9FDhMBnHnDNLJHUmpF0WSaPLgMxOTlKEErKUvdMJmpjetHujJMAqUhoi2aBxU4l+auGstFqSvpXMtqfpcJaWKannJCq/lqkCY2uHG+w8GZWS10dLQJ4HcZ1uWCBxaUTQWAZXqjjtm++cs39KUeHcQHxVPAfv9vaCPLAPXcWC2tk0FZhrMQMQoJVmodkAjGi1gETTlcQ==",
        expected_client_proof: "y4dfmOQQfsXUXRwmst4CstXJdGGh7bs+Kh0EQ4O+URMb5yV8yiQax16G7DHWy+eJvJ4+0OVGJPSjt7EnOINqWmwNcWGtCkJrL7VZu8Xb/0AlQk+/eWJ96xS2QEaFoppnbOtNFRr2KfH8mvC6OOyjo2DZByODNFcPnJnnrf2+M/PpQg6Pu5RPzcx+uRPdPi+TONQxukr0q9S30NgoHNAj7pCBnBsQxTV1qiAYVvgPMr4NhKqaHoZBUCaNMZLzzfzFtjgWgBpyivyNpXY9JTawJGhZ5GMN/rQFIcfcjBf1M+u/jtOUgvgn/cXYqEFFANff4dmntVEYXMmkxvK/6Bz7yw==",
        expected_server_proof: "PFfxCPIAuFNgsywecKfcWpsQSBECj1dpR3Rsq6Ovu4KBhhoBmNVIlY9uXev0EC/HwbQ1b1jMtMNilqZVFxrwcxmnbojjC1t7KMbsgJ+rwnwSvx6+XuG5f4vfpWyo36MG/5a+1mP0Gmuj86+gRnLkPSy+bXKZvrE8wOBEAlsYtHyUc9JZNMPnMlD6vRC/QDPfTAdsc2qe5EFfua/wRygW4tSKUac6AZjWEi858K0y4ztk2erZDdTX0IrmX3ytfUJmjExAv3V0N6mtpBdWj+UlIWgcTSr4t+DclJ4QLlIRQH4cpY+U08Y3TSr/89ZPhsywrBEZh0P+CBjKsOF07haPyg==",
      },
      SrpInstance {
        version: 4,
        _username: "VeryLongUsername_123456789",
        password: "VeryLongAndSecurePassword",
        modulus: "wzWFFf5nOWQQSjvMAV8wefZxGsxuHDXKSu1ahcNFslgWC3PjKh3B8b2Dif6Wt6bv0cqKYmUYb+JWvWfbVQeoHKW7uhr8boVHlDQ/LfkRgqT67IT6b9wwKMhd40TvVF1aVmjPvgDQqY59+cTjgzv+SeXpOPRljSPreRdXhSpSDHkIRxwkkyT9h7OCoXlzy7li4g/NWYBRzEPnkgE0EmAylKyv5RGF5tV6+6wT+D6LGszClglLK212uN+SEP8A+6/rntMzwSOvXg6GB+HuAayAp/vsGUlSBQwQDRzwxYdAUJ3IKg7m+CU2+K0OZRKE6Cd0B7tiXdojpc2QawC3bSHa3Q==",
        salt: "cujclj9P6zluIQ==",
        server_ephemeral: "T3GLZweI6zX4wy0FW9IHRO7uHKZyXdKvwrdAbC1YN90RFZfoxXANTnrh99t84vEv/OOps56/QbzRqwtdXqRCYTdvBIH/TNbv6wL0/KYGE03Dvnwy8emKsObEKJ14mrEsCNyQBTGuwmq25rzpXNL6bvCnChtBolt2XM3IGlCwuJzA5+/W/YQKDqcBVEOgAzFHyd9DH4ECxFMPtPKgQc31Mi9+2/r49kxeH5pk4mlErZP+Rd7wRKKauaPrk8izrNZ5rTj6mBgdQnYj4cplXdhh/9Gzb0huicMfkVdE4V1zfiKBz1lsr+eSRlb6/fKtbm9KNXFE+o4gPdRBKm16LiioDw==",
        client_secret: "jAxeAV+fXGPrNgVtoPtV1oFEL/qBOMe8k62lJpjKN8U=", 
        expected_client_ephemeral: "534PXY6mu4i8DMQkYvYFdmcpFWmrhithmeCUhZTsI/1vl19ikAipkV5iOjTRZlCaVN9q3wk9hlA8MSP+pPSVpH2bZqbrFfnjNUjtLBXbQFfdK9AXn8b3qAN0GpE1gENyh6KzU9702Y4zG9kcEsNhWB7ibT+aD+gGYXHBrkqjhJKH737bExrcMkrSzVcXAuI4qhF9XTthek/hek88jf7W1w+iGDMdsG76jtgR5VnYgkS9dD9YwCS+YI/oc1uopJVx/bFmA3/kfQ+H+BELVhUQFPOa+DTa3iCEflVgT8oZtcLQvv4kKSlNBANtu+AXdxTjCq0M0uPF4gNgusbB750KEQ==",
        expected_client_proof: "eyuS+5aAqZB1gUyJQd/4z8BzEZtfj1XD0lJSUvduVT+ygQL7VNd+XUEjKu9G0mh35j17trbNiQg5lRNPw2/8BdhaI4uucBP6BfprYQYK5YcEt937Lrxe2FAQCc79zkNrmNAe5TktBJP10S+usBahexueBJKyeggoqsQrr0mkRJtGeV4Sq/7McAyTh57ZsdntoNzK5NOGMdLvultO6z2bo+IJTMFR/HU1YJdJrYxn53yVZhx/eXO/x7uEN2BzmjZlL5hCRXVmAtdX0ofZSOWBkfrqROKIv9FfIUSQBmk3xjgTwBe9ci37MhuSNd/AhifVVTXnfaX1wL3lgi0klyDfKg==",
        expected_server_proof: "m5qNgT4G7GUF9BVkEPCgu4MoefwPQmkRAfn8KCwGX9qJSZNVD4KI5ocfMtL0tzUs8oNssz+v2JhAW15ASNoMSJQYGLAURXF80b7OyCPOlDfpbhUKagd2LS8diakQl9ZKwFn+b5GeDpfwSnlRMY4lqNY2rRzLss38Z9/FH0cyM6xoShBTdyU0O92yDVpC+9vcQbr01xE4/0YroBXFRWKiz3TtJGrRZRKWPzCO5SK/1ARrJ5hs/2P8QtFKutxy/EMbwIIUBG0d3r9pl/z9sNmmBzXd0iERMiFRhnSxTb7BMWEkv29JtkJ6uaYkgEIroRCwRg0iAAg1MsxAstH8l7nYiQ==",
      },
      SrpInstance {
        version: 4,
        _username: "TestUsername",
        password: "Test Password With Spaces",
        modulus: "UwuGCW/iuoTL1FGO4mOGv/NTEnvJVFU3tVFIN0YZOSy5DAXqNfADJYPZko62MJZCI23w0usAc2vYrMNJroCUyX8zCu4PST520cCSyYxhuIDJQsVNm6CuJIOq1qEl5gFoXs3YvZhMTxXt3sjSH4c8XOL0exYGnZUCP2yvLkwlcD3PLgnGbjkn4Z1MY3fVwx+estiB6CC8uXdHJ0w/Rl3zwXv6ycN99rJVIJaXdVrAaFF6GRNkv316OjtDIWBqVAWQ1woaCu6lgLdzG4nS0v1OxdCrZe2RdXBBweCIq8jEusK5tYbbA28DXwS8ntat4HE8/LhbrlVsTT+ioAuc5V0ExA==",
        salt: "vSds4CNJcRFDog==",
        server_ephemeral: "1uqrPByMurl9QAAUK3f16TP1zeAmr7BRmoFWfFk8HwaaEZTbIGQIoc9iaJU4cruofT9fGKHMvf3a/xmGyDW3pWNSDuny8ZqRAbRnDk8AjhSSD8MC3gmjROdqdKIblXms0lZNWRM6Se5NKDETNnAbMEgE3w1jII/LZdMxedx2CnXUlIzsvDfNn7O4DPGwYc8udKBY2M+wijEAMOYB5taHucPfMuljy3xFwff5Q2QhRrruIs084O/2HiJmoLrRl1UdWdG0mWCcA3PP468blbmGioJyeDgVK13DP6MqqEEkJIC1g9XSK4agAT4e4aYjWs3kvbAJAeZ3jZ6qeEiRF2/Whg==",
        client_secret: "FlIvuIs90h+JXeH92NQNqZR48pV2Be/EJ7EktHGHkJU=", 
        expected_client_ephemeral: "g0QzXvAHveuWfKjutUEu+SRodW56Cl1KhvOAiDVoaRdNCIRPWc0k0k1eIBL+hHRrEX3nGuYoScQYsP/PoUXQeqjFETJOgiNUfIqMC1oWBVCkkx+J3XUI+7HuBBRIlnrw32AwFgsLSYsIp8tABM6HuD6PktcvY74BmN3TiCsswmwo/sIzJAsTcOz9p4FKvZMUcNyqUuaG/mbgX4IY8Kt29OBJWY8cuOxJsQAxs241w5UQ/1403S4EhyKzsDsMGPFbkocgBFm5RrKLq1q8Bvg+6FlR8W2Y+MUzRl2LZedhEiaendoRl8B2/MqzYuqgGK4d4hJ4Cl/az8kLGBCBqGg0Nw==",
        expected_client_proof: "BjI+CWxhpgtzZhXO+KR4Vr73Bqafu75bb6CPP3LQH99xno9iqNA4YBeTaguucL+/VayorNTKzl8wi7aR+0Z9UQ2Yy/0HF9m53foT3UB7r6cw8dl32gjp0LlSJgktCO3fUZ3YggJe+klmxd0vLpgfTnepAGpqm2pS9y2/xWPelEeQu3LWn41mDy5rCa8pErBeVPVWzvaBdHXdbMGEbvoKLikw10lW1rI8cjIVl0YzjHSLsvJSVVVnNIwtzKfi4Hei821F5KvTzRzUb1v/LGxGy2GlOJ+RPU8EHvpTIjAC0SpW3e65eAC5/6W+W4BH3sh7bTCka/+YPKZcVvMtAb6uNQ==",
        expected_server_proof: "PsMn3TCj59fbrSfhlQ83uUlEV1AtWN2pmJZGRxxkPH7dghpxzUYBTpuA58FD5mBvEq2x0S5QXOYPkB8ahh9WlEqeIUUY0qP6bnG97fCqx7z1+YPT9nHEzL9T9oDSO421G11seoFp4U/XKBqcj7XxoTL7kqkKVhkl1ABbKL0D3JvNlgg713FjcjWViZiFcsShi1Bnq/HUG4xLvStlHGnvw4oeDMesnuvQonkZzD6SA+uw8RCRTW4YjRvvopWtYzEFepz4ry/aX5qE2/uh/tPPSNODWy0r4rMlRYAk1FztZM8wrC4Ikw1PoAh5HVrJ45moQJreLAn70HE8VWGMXe2VjQ==",
      },
      SrpInstance {
        version: 4,
        _username: "Test2",
        password: "PasswordThatIsLongerThan72CharsAndContainsSomeRandomStuffThatNoOneCaresAbout",
        modulus: "w3Y3esbGJpfiEcC+gNo8X3tzgauS2UU2tAZZStDBv+kKQk42CFzS9VPzcO2GPnJZchDdlKGbDaQlfNGO7a8zpx5b12V9slvmAvBDD+R2LZ9hAN0xnX5YcNwFg9B4KDLmjooSwaoLgBj7cdXzya64AgjeYsqwZvzIDidPMhmaohk4guJWqG4riZPHJ4zkcLpKmzFa8zwCmWfrlsRwmH9ED3zUaIByuY3AtXaGtYDedr8Q89J30kytASqDqYqDT5CiKinRE/Jyo451DfMYis/K3IZCt/mEfOT3Ievx2RBb4zzcGaAQgKlCf092sn0/z4kmpcSITELRttBSwvdERSKD2w==",
        salt: "lSIG/btGTkKS4Q==",
        server_ephemeral: "moT8ZNXymyDwt/9TpLdtqEpAp+PNxosXe76TbbrBi8+sWskgdMzrS/LlDINlGHRRy/gsd2b+Xvu0w0Et7VblDHKGLM8raywDmcHOJ08StVDV32lRqWDsq4LvlGEG3/f6DflUXk1De7Qf0StbFoDqRWrx4cvox3SAjWrKJEj6Ti2R5gy+XPwmzBWVMqpEPut67L2OHP0vazUg4OPokAA4N3NCTv8ENjfqtM8SWCtwDzU5K5vArgYqqq/4V3z4Ox1VPxEOCBwETwdfL8q1CM/ok40Pw6KBGJYK+aDz+60GA/MFZRWQN2Fuy+tzPfCLZBtFphemQc/UwPGW1h/4+ZuxBA==",
        client_secret: "aMMFeAJsFRxrZkMXg/HW8vVs7s3dws47HTZoT8U9l+4=", 
        expected_client_ephemeral: "IIhXgrBwu3ARxQi816Mk6t+AkOphkHZ8+Pmx+c+5HqBLINpUncR6UE0g9OnYJQof+d+LDs+5ynN1AaELeiHD0j0Szm7By4iC7BaCbNtm5Yhw1JOyPrSGDYA6Cqgjww3tTpAa5nKeP/EgFPs7/Zq8y9OkQMqDAcy4BpLd6+BG0Ptfk3byCXH7E34wgLZwl5+YIpgJu6FLQXVRYOgReezmJGFbDg79oqxFU0oMC6+Io9upptjbIPERqZjSH6au26P9+8MusifHrxPh7u3dUUtZuPHe88clU3HubZ8sGh/zuhUvZEowSwFLc4ZBlG/aP5QNmRXQdDR9C1kNu4/KH/wlgw==",
        expected_client_proof: "pQROwmQ5sVlrRepFlLBMjxzldxsPIqGRKhS78VmUp9BW2PVJbOojRukPVspY5b0UDfBtmd2udV6LRpreGYKK0Z/LRHQxzSl1QOOJhLtnzXn4DBjwyE1dEXE0X/xhRLqO0KIJ5Tp3h2CE9KuQ5FD1pOHNpQCN0Lens9lg4blNfOJqtrg6ZKqjStqLhFOyZh0qAl70/FOB09X1v92ueP2qc6z/Ugd19Tz+2i4MNkilP88A1nFvc4ayypTNng4p2wiBepVOCh3QD1MTX2bYUObA/sIeRdnaE1tehoH2dsja6V6UPwkZMoEhZpf+xdYEVp2u6KPh+8Bg4XpOxzbhvxV9kA==",
        expected_server_proof: "nl5MUQ70wpLe7N75fkMqiheNNm1e3v69jB9gfvB58b82PwpVRRQCCC+jTOqUgh4AIjvkyqI5VyXK5/vXt6G/3Vcr3/VNkqG7yPfr7VFvwQTAxJId6qthORCOtApXqokT+qoqNiCGJVS4hW5uAAfq2WT7YNGG58JQ/WmkrOjv3x7UdfjYKLUWTZqIRD+T1W7bbmOBkk+GWVGWf3AgyUPhQpNsaWTDkNkY6YcmXliPIYc91faupKgbZXYhAxsss5rdhY5V/RycHCFYokzsd3qPpysqeHYMgyCykQUcLN4kyDe7j/gtsGJWJZa66glmKvAZd8W/vvQ8O9N49Dnvt4iafA==",
      },
      SrpInstance {
        version: 4,
        _username: "Test3",
        password: "Test3",
        modulus: "a/jyYc17HJElzLFvb9y1nh54NeLhyD1DtR3TGcy279xW93VEhTj0CyJZ3PRkgp6eLoz+nopWWKVCm7z2WSjr+RJ2iWFIuSDho3Gb/Aer3mkmW5KWB55TnzsgtP2IRX39d3bzAPeaawH1Q4+AwFouJ9GQPCrtCHyNFWaRn9pEPWHmG/UJXM1fWem3wS5iEBOKK0jsOTEaEkQuKYupTZlOADhyVwYITvmT9dEIhOntEjWixy5eiib1/wv3ex+Y2E+Ty5o1mN5kfPKs2F6RVBWTg05yU9xBcmJIjgLUulOHOx9/uheukKGJq3Vi50aR85bNjJkxHJttSBBSj8NpiJW+5g==",
        salt: "rPelup77AgUCQg==",
        server_ephemeral: "PIDrmYvC5873MqDiRB+un43h+cNVS1AQ47gglk/dXfxUvG/ZGNYt7oeZXgscKehvxS/Z1tUZo0dMftIPjMdWbvkjGAyQuxGRTe+xObdRl30JG5cuMZvht0Ff63N5rRfQP/iTe6RixB+Z0lUVavzM5XkqvzDPn5MBiQaOnwFGxUvfXLjvPj++4ACBWEpVKpNpUbaQs5bQ8C0XMORSNfbYm8cpCo3TLritl2LLaj6uNLjPKXwen2l+X7P9yKxU+ZVb6HEYvoTUao02gQtE+tG6LJQRYgoVWugAwPJ/drAghZB6ATIcU8ofCLwRosX8Hw8QfiySAYZJlc95isY9+3VN0Q==",
        client_secret: "xy9Gd6oVu+eMizxlSuCh4PuOVa8n5nW/lLBfPBQPCqc=", 
        expected_client_ephemeral: "xab+QLi/IZfN2hS0fT+WZtcTsPRKhiDVAxsp+sCtnZchVugVANbY6QL2Ce2ZKObsrvSjrBfC9UJw/2EiJoI6yJGeB2Vo3pS7QX0D+KBX3Li7x9un0GI0dUaOyVKu9ljrzdgdYxxTBU+ovH25f8Kj7ds7d1GVUGqaT17q0A8zcskx14d3G0AlEPr+U6tj0v2T4buRAYSPmhBxAdbisWJ/JxOwW2Alj1rz2XJwLkE7pYMdACLss+stxzPVe9fC8CgXdpAmjPWdNmFGkg2TyTB7IVRgdf/rLU529d+fCK0Ue5XC0q+WcJqSAlA4fBv0+p5elnOubG6FcWoWJyWzngJIcg==",
        expected_client_proof: "q0KQ7oK14D6NAmgZxLohFPYxWchPlM08++9ewmo9pOiQv2V2irTCqAh/zykgNmjKI6w6uMTCejPynAg1Hb+79Sntz2hAlMNFg5M6UTN35h9cWxhcbQ+5sGAT+uJzgyHZRBTmpgbX0aH+8PAirjG313hZygYu9Mg8KF3DB6OIsZY3lAM4lHtAly5Hy2CixDaHQQHGFLtuFJOeJVYIS3db3hYhb8Fcq6N7/Bw4fvtBK/8x20wVhnTKb4tPZYhyxWFp7a31Kl+QoQT94NEJ0ySNNKOj81p6ZrekAAV4y9NOJtLBQnwql4FPg+jVR2s1xxE1ZoGC9UMxHHQIvoMVCfY3lQ==",
        expected_server_proof: "W5OCrwQYOL55LFcKMKbe5afJcg68z4zapxhYTMFGx5qwrzVU+12NrUNhIcTtjJ6cMM5NBOxioUusJcwn7WtnfJKLAwVRJOWf6XUfh866oBUyOg4SPiRYiz6vLPxe/WtBF2XBtTbhwecCtAd/TOnVMc/acbtj0QfMYZ+hjB9XlL4HMBDInWaAv2PgAZmWNRJI7fqaby/bmmUZ7iT4KdGKvXotQ720M9jwXs8YK0ClupL6Q5aPzLHEmGmczA3KooEPWfZ5n7fySsjEiq1fuOxMRhpOx1VF3rgL4BKakUNJGr1v+xsgNMT/u0ddLInCicHtZkSwejsoMQckMXAcjCb4Vg==",
      },
      SrpInstance {
        version: 4,
        _username: "Test4",
        password: "Test4",
        modulus: "8/wGq0/O0KnnPYWCbqHCGu7tl4w8k4UkJl4y2/oCh5eSeO2AmQ6FRCG/GGEW5Tj4MC50mmg7knJ5X3A1LNmFVOb7p3FLoKtcAqHMZBu5MfUOCo+PsxRGwhlQo2IOUU8avu4QK7iyJd5e80sAZAEO5wz3Nx0tD8FUWG5C+ZcBvqrh6/wEGnl1p4KjRVqk7eqe0LEm5N7HRuXMxpa5UR5h3Awmp8OUOPmcccqkfxvvP/JfuMYdIKnRkeW1YnP6kMDTEKApbiuGFW7uwnU2oyUq5O0672cI5sUdRk4O4V7EtQ+qIglXkNT+k6a9z1cto2hQAVs96IJAfc+zfqRRduIw4A==",
        salt: "dRuDue2lP/mG2w==",
        server_ephemeral: "5qB5oqDQW6sSsowJj+YHpL/9mYTtSnhWK0gFEmULuao/TeLKJvIPaT7BmuB6YznPIaYJfxeqctlaxNj9rkiBH5VJ26Ytp+NyD3RODiqM9VIxGZ7nuRz0Al2g4X8JTrj6WjBi5TU7g8985aKAEeiWa1icKZhhvl/hA44MmhE3BS43HISfNRrh5zP07hbnBENR7NrhqdMQTYDulHwcliNLq+hEKLLEpln2zMm8PQ8uHnc8I4d7MpjGcjFBbePitkGtpm6ErMa3L4PatZIoFGmNUHQs9oYBm3SdikzAYoTGpYzJJh8VQEELfAqMK+mV+VHHBUq/hF0l/GUiycbEXjtbiA==",
        client_secret: "duWakIBZ1HhmxQmhhRkyHVlUyVlqyYTUcu1k0mQg/Z4=", 
        expected_client_ephemeral: "8mOhjkio7wN/0QHQ9FxtwvGfoPzNwtpiaT2lzsWaKVmY7My6usTyNqwkvJRzTapTeAzc8mSJeQeV5YOwWLS5+d2l3yAuB4ntycGTDnJpCx1gV8g5LS+7V35EIvr9WLwRpAPS+7LxwBApP4kRfosNd8nJiHx5a906Phxd884D+GwSdgAOA2WE97o2qSLBdIiqF0fvbjzGYMV1YPgOfKqAGPhrsdglgKazmD7IJrQ4+CoLviTGblx/QxLwQFR034Nz9mAb5ISpgn1/GhzMUJzCZXjIf1cNfTbXBi4G/vy0hrBNIyDFqX1zEFqWt+gteo5wOQbXS9gwbg3kC4Ux31VEdA==",
        expected_client_proof: "o2WMh5Ybge6mvkvwEpgARrP4Pn7IfNONyh1bxAmwSBBssRDB2GRpc9/stQCGYAHQAFbdZ2NthjThYD0/RmxxoZy06VRXBEM1q/qlWkdjywdEIMN5bITrXuAdJuXB87u1cyEPUwSh+O7E0wlhdMMJBN6rGOF2GNOh0p9WDuJkBEJpRdwwqIhbxsk6TqxicacOLhdGhqE9SS66OsAbyu3F2wafwjkE0KAdCWDUrsS+4jUltKIqYbfnfz3N0a00SOUBO/tCtnNO+GDbSN4029PK1I/kAvZep9SL/r2T+FK9IbqEuQuzkCLVX4D+3iivyCXmOASWwPgbaCwdY3OmAke1Nw==",
        expected_server_proof: "CEQRlE9cO5G3n8AMIovkB1ZxfFPBMbQTZ9Sh0iEnXqNbzLlbh3oDZT3rRH0t9RLi4cvS5HDRwJ3lgcE0dLriMK8cBZq9rKRH3WpDjOBqTyAbSCmDuHM10W10RTQb7MZynDkWuvAbYMRuWi2guoGqW3CbMxQ2ofyoeaczkCTKDK3aAvkNqvAxIafd+HSxPLJGzvM5yJj1n/hIDM8pMpTxt4CjjcY7QuVQaNZTVrpPSwdqYDFd82cwB3JBm9YE6ZR2iItk39V4eKACO5NRU5Ydg0Tsq5DiD4zpQgEh4GTgT5VaOAu4ZZP2Kwgdf/N8YB6DEdic02hs3xvTgeAegjNI3Q==",
      },
      SrpInstance {
        version: 4,
        _username: "Test5",
        password: "Test5",
        modulus: "Q06qM078EiXTdrLTjcb99OHhGCq0tHgDrp2sBYZdGpHZXn8wGLmJPrz97V6mytKflTF17iXtNa5NmzeZk2BQPZ0+uLMaKmQTmpkox81GAMQzASzlLRBatHGOwvUl+k8vTltDdr06hpjjxs5g6YZG5x6yaxhWXrkMM2f/uc1Pz4/fdfbp3jDSUtrtg1vvE9Ie3/uBY+VuvPstiErix3eOKCefYSUvXiTHkQOxYHipgOj27ZpipRGHtxZqeuM1vnhaTejF5b5O8bC52/jDxCxEW9I2snnbU/KPdoWrxECgm4zMTWsXI4Zqu97pFsxfaO71+QKi56FYBXiNvnT6HyCu7A==",
        salt: "JNmIaPOOZEzaWg==",
        server_ephemeral: "m42FN1RUk9PdzUlfWL4gwFiDcz86UWvJ0Cd950gG5C4FXL+kC/SL9MWG+FKkEzNPLwJGrWYL3TlIC3N5EjO1iIqGL1TTSMLMh/F31Ts25M0YOMfU9+JvPz8p8Wg4LEIamMdx/ZdhEyn4WGcJ3ISYKtoRzfxvIp4X6uQzfzT6+nRYrFfEVbPhZSx/y/EseeSZ+fHd4op1VrI9Ghoy2Hj+BYZoha1a7e9F1xd2p/G4ulWbPQbOxDuiTm5eMHRyq6O5BPJzNYCdThc1sGp1GTqRIrudiDqvR2S4zeYvS3BZdC4d5aqUC9vgsT8jJdRQKn9WCy9qCNOeN40Hng1bRksFEw==",
        client_secret: "g+Htk9Cl+ENIApu2S3hqxX5NyfhAv2shGaRKl1vvGs4=", 
        expected_client_ephemeral: "Ay1SVCrl3vAN6lZj1VecIq5BqNAtZdAdVZljaDZqZrDX5ali5dcz1AsFDSv/8uDWYG6ksxZ3zK1jlySc/iEK5kt0Jrb20aOoSZ6tD9h22I7lm708lN+eC/SQuaBLkUPj8rR4w5m7BR4cj1xpeG7OleUarYM4WzkCvNOFB4HgTfoqiJLpWUs+cp1oyyN51cNgq6ap4DTFbzndS/6Ma7D09noKv476faiecIVq0beulWJwfEi10P8nxGbBBdQIFwz6DObjcg+OTBJvKqBNSG8kNA7y35xGRgVgmuC48G6xfWUA591FrNw9yfWkVu1VEaW+B4r3oq/eOeMLC+k7jAUKow==",
        expected_client_proof: "ZfAAsCMsAYIYY6t7SG29me4IMDBkl0oYqEnF9NQUmoiLrzl4N951O4Ksclks6mEBmUEbE1crtEloX6hRGDUD5juPoxrkvqx5TIvoWcwW3XhTom+5hjXIqvLd8vcmq4YlV6dNO1YadamBbVe6qqeJHqSqV71P/qBl/3/WUg9tLItku9n3G4pxfCsaj2FTuaF643X0csH1pQI2mWi8s45YrSFvi2FIsb8dOrhI7EBa2Q9MQJijqKgqyzRPudf0GI27rW9PVji/vG0qwYovYRUqHay+/PiuTwIdi9632Yba9QL18t22LPgDqoyQ4v7UwJ9ixhYSXWvaTkT+NS5vrGZY/g==",
        expected_server_proof: "5TG3U7dra2jIvOZu1ZODDQO/xabNCN1SfvqWOSlU5g4VuZTllz5h22rkVD9alpexj4qu1z5zd8Dz1DxOIihEJzZWed9Cix4CQgwQ7mZosXtYrH7dEyf0OiN85eMxa3K9Npct44N702VB393WOwXyH5fEwgdEx/c78g4lJ2gnBNOtH8sfKfP8Q02TAOEpKCPjfql4vkgl2xcHXLIO14sFhCWFH/iYqAwSO0nwFY1bpRON+eWrykcCZkgx+/AWCdf1BT5W5mIMl1JboFi8uYkoM1PTs7t66z/y4v8+uPzzpr9wcWqEWyU+M8TEM8d5SBng1wozpM/Zqmu3y5XCfpVDxQ==",
      },
      SrpInstance {
        version: 4,
        _username: "Test6",
        password: "Test6",
        modulus: "W6ZWc9PGd/9CzSI8YTDOmR2zRbJkfdTtGYgf621pWsX7M7QC6BPPa4KTcuE8YRdAo3sjHzA08RQpUPi0ilUlD6qsKfvhKxi+OFIlj8jeN/UyOO5o34uvQbS/Ts5VHX3pG0KKLreN24bI8VSyWT0Y7uMzFEHZj4avzMr1FCTo4grLhuxHj6f1loBd5wBTIHDrj5Dmb7BQOFrP5+1F8EQUSWKpcycjfrd/KpqBDRjp+zZgcOiDFYUvWX2ZGykUhPF+K8ARUooOn3VRZnxnQKQTl+Ip6yTJc1+BRUavoX5amZtM/mWgjr/161j5C/K9rNBL0AlnrwHMoGYIsVcWvg8Fqg==",
        salt: "ZLpMUnhDn1QjkQ==",
        server_ephemeral: "z3hJrYEF9sZUchCho1jvOvLAFL7XcnVVx3N7qj85i57ffKTydx4sg2D5g7b2w6VKRo0fszbcuEVHOcVUjBXkOub+iRx7Bx2b1JdHCao/kvB0Pn7aD/XRygUMoYPUB3gM9Hij+FDrZh27zl3rgPLt+i4IaYmfYCFnA0Wta68pbdFpLJiRiW4zbfo8/ZKoKU5s6cEJwkZn/N5yuGcpH0qCGhefWlbOHJBxq8jIOkjzDwD/GetKbdrtXPiVBP02rZPbJr5MdDHw88Ng4BIi9pwjFtndVpGo6Lq6m8LvzT0r69fe954vxvrJIMMLXxayPxJNG6jBsdv2kZXv3fr2XGOpmA==",
        client_secret: "+p373nkdWSW17dvG+J4+YD1T3ooGuuOPCHK0UXGHpoA=", 
        expected_client_ephemeral: "tv8HeWBPCp8DNJPN/AA72LASnkYFi4k1al/n/3aZnPehpOhny/hIWc9juKjbm8njpo394ljOTk7YfnSnG739S9z5c5r45ncnK/ayCQeiAP6UZi4u9s3ZBC9cQGcUt+OT7KoYeAHHLosEuTiFsiVYqCnZkzTWCNrwEAx5P/OOhlEsZh8bZ4PXDqPmCTuGhgRWtL3dPxm09dVYyIzQQS9zJwGDOR+H0Vx37M5FoKNhIxMJ/JnboHIgVl3rsJ/nSuHxOUco8xL0T3LHt45p+RpNk1IUypa2DN8VOlxM8yXTTjKWgfAg77KPJH87kPl7E1b7EWJcpRsvpLUyVUKhz9XHBQ==",
        expected_client_proof: "Bh7FD0ePHXMJBQyoImRyRCiLXiArusVn8T10uzLL9QbyB+79j63bpSjWh0nNueWf6fwNCxhlkmUnpwq6V7b2jLTGfUCmgiblU/hf1kHrnUZXaupDiQOVc2O7MSSlPMVCYKEtDEsx5zMjdErgzFJI51dZDl00bm++ltMWW3dsqG55hAHtUilIraqxlf3dayG5KDkVvD37v/L8OiRy1P9GASqXMH5gbC7NiPr5v5ZcgK5yOItYy8S76+BBU9zl+iLq7mwxIA3nAIlb2p6iBKMGmZPj/OLWnYd+U5vuEf0ARSbWyM39IfOJB2evatu/qm9fj6N1LuFGHNjPOId6qJ26Lw==",
        expected_server_proof: "opDAqBzGWC+E0ELrPpa45Z/81G/DOHgOH9W0ngtyPvBU4TIFkxXRGGOmuPSMibuQAyrYis/rG/QByGtdjWu1KVm2M38D3SnkqKwsk/aO2AaY3KXpUEu/VM2kUjSfU9WVGpcOsm/dbXj+OD710wPQzx2ng4nyCkbLaJokXvhC/rESJKL9svFWy3feqdw21b/U5+T3ljFaa8CZl+PCJJ/ezeZWTmbLoiPLv0FW2psMwG9MB6qkJbMeXuGC9MGJWBt1nY/752Bhz+k7VwyF33+U/2ZEJY9bireJa+Ljbz2jPWdXVXXxMGhsm/IzBiWvs2jPRYmvGzFNxn+1d7E+WaMblA==",
      },
];

const GO_SRP_INSTANCES: &[SrpInstance] = & [
    SrpInstance {
        version: 4,
        _username: "GoFlow1",
        password: "Password\nabc!!~~ä\r\n",
        modulus: "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==",
        salt: "GOz6DK53KINQHw==",
        server_ephemeral: "OJIMsw21G9EotvTT0KE9cCAVor0CbrcHz4sb9tkFse2ajdoPPFHRofksNdt5CuWFCJ71YPQHPZthoxSeC2Fk5zvcaeYmsu60VFNQMuVirNIJ1Sjxt+lDhaijYBGQfpO/S+wXkmwXSju2W/x6GJO1P81OdlxU93K8NKSuszeTshU2pMBBfw+OvS8aBIlhc6uEjVLnb5LfJr5TIQ+rPzoEgx5RX/gVkt2TaJHxh54n8hKUHVAqtfOm7TkEifivtjjEdCVv0HB+hdh2L5SCtbf587QAv5ZOzW+01j4QHKjoTvn9m7zsw5YKh67t29tPZr30dJhqdx7QzbxRgfzcLnCAgw==",
        client_secret: "AJEQAD88tXmRiMZKtko5axZWp5FQLEcOiY64eNyV4ysndbh84TjUq9BHMbQ0T9caghCs+z1XEUhSQQXoLca4HkxXINCmKUGvxghYxzMl8BNjUQpyeknwzg1SVGTcz+UuqfXoxAAckX89Lalwz8WnKMxi58EaL1iBN+Dck81OqU0uhFaxG6msquP7vNJ6zp9LlF5stgK+nigkUCGeAMf/k/TdVoD6R7G1KLqQqVhmGnEvw6CmEFYvwA57QOH9KSCH3zaZfwMv1OifhU9hGj5bURcKwWCzcWnaRO2TcMPO29cxX3TymVgcWizSNNNWPe0Xy+wudff2kFXcqy+8vt/CAw==",
        expected_client_ephemeral: "/zIfD0CFHSS8NLqpiMwqeKQt2hAuvypxjY1+E61mP0922FiQAXzVU68E7ArOjDWlq633/ADK2ndW5RY3t0r/92RVBl09Fq6s9CXEaOGg2vxnSWXWz8seAIkEmCFGKijxim5KtsK7ecbCSgCC6Humb5ffqtU7rQOGnZ7TuPkUv9Z9kRBe26iR6pRZIWuADg6ioxvXQuypdviLwL4L+nOBEMsIf7iIpMf9pbl3PsVC5zIBt9CMB0Aln++EEs/wf1oKXXtrWnovRS79X/dELWLYOhSytIzFF151SzmXIxjMQmV8PAZdvlCvBCVmCwFm2+EJu465Mfnr4FTBrtmaGYNlmA==",
        expected_client_proof: "UqekG1kBaAPatBxSyxypv3pqPTBr32ucB/NPLR/ZAuFYL8RVRrABXBJueUREPb7jj2PkNtH7URiJyoNg0WwMhobOjimBOEMEmsBYE7+ElrGf1IKrE647B8AksYEKvpw4fof2b4tuw4MyYPJd1NtnUX91T+qJ2Jpmg77+gJqqE56lzwHrC/NmjpQ4rxMQsGZ4rwD0uyknGGgGXhdPyj08DtX40RET1ynFrP++Et+G01qphMbyniNKp7+OTxuu+WzBF+XiJTkRBR48O+yAhuC9P980VmZtg9HKbHICRrs+yFpTf6CGq1BjWrfx1H9ccOkXg/79bSvc1OTK/f2F/5EkFQ==",
        expected_server_proof: "H8FR90AJ93/3jrJHGyuH5Z7H3w5cb65bdolDCJNVBdS6atvNgFCNAF0b3sfOMAbVilce9p2y6fydeX1WRqnKjwLpVLCOHAfgJuZZ8HDOwe9IeYwn+U5K8pNnh9K7VGLdqX+8Vt//iFY8SzWvYHM408dmJYRfCuOo1wvcTyb5aHj+nMORlVfPAUTgDv2HSwfbEA30j1gzEtDZTV1KmDc/mNmnDaE8MM+8nFdru+1hDa9jSCMHA41jXIujaI5y4lysK1sqgpJGJSYiUF9MgVbWGtqV921JeBPKn76sAsgoQ85Sn8wrFoC3AqzqKofRDVPKkGMeyobb7RJ+5s/i2saGMQ==",
    },
    SrpInstance {
        version: 4,
        _username: "GoFlow2",
        password: "This is a looooooooong password",
        modulus: "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==",
        salt: "zm2TS6veJe1NXw==",
        server_ephemeral: "ib78GCpEea1FxtQXsuX6vdfYOBPjKFgDBeTXxFuoDtHj/Fv4l/eTWRWzO4jjUkbCQvRk8wxt7roFWKgdHd7uqp1E4gN7itR7CREIFEkbwPMgOA0ApDHKl3/3n4DPRkpQMjgAZzfXa8lunGPyxaPbPMPGc/7wOBVn4QvkjVQUuC3OOXyr/GnG+OHESAqknMwfG5FzGWes8QG3YontBArENnvbYK/rOo5aA3aY+D3Z3Fl1vMjphnX13T7dzibBBYYm6RUl0pLEoZ9RBK3w8zpM1P0vcJFSOGxnnjfquyU0NpCt6+zz7kj9VbvB3nLytInTfvU2+kxdDChXGYBMRSN3Jg==",
        client_secret: "gySv/0l5MvnsaMZwG0XREYvzkny+3pyMkpS45i81IU+jYPC1UidvU2KtQiBT4ZtRFzHeg8+9emTtAh+vJ3GPRyN2/U+huejiBUq/0/2q7ois/MsmgyupkLCUGdYOLQi+CWQOWmAtjkI77NbyUzAEsmPDa6D57Fc0TSDWPASkVJX4aCzr1KhSziutB971fgKLJTNuvnDXzmadL1Vzu5bhB+YihtFfaUtE1w1EBrposyRDTvXJlSB4J4ppYdLOeClJQSKvOc+sJDVUfIqGO4VA54O3L+DT3ZGJatpsbX7MMMmyBUeV85a82E3yDXePpB3/Q/ARJ6bXcDuv29QZq/CRYA==",
        expected_client_ephemeral: "gGqO7YyBE0/5woRrnJwD2BePNlw/+s7WRD7F7h8yvoI5OBuxQlIuw+SvQm7vdkNlL22GGFKqWJ6HyB7+2Jw8h7H8t6TfY/IMBf3ojvERn86jFiyE5GiwBbLNEzDhWOSovnIk20T6lp9YTsVswhP6ExcQDUFC1L8lBiDsfG92Bg6mnOmznwe4eugB75KAg8BWmJkD1qMG6NFmtTit9Y03xMsGwjwoNWEMktun8CkbLXxcSq4xwZUDDzB+j0G+bwOczYBmejBuYoqWJTGG5CgzcQam1pQGXwvAy5RfyPrKbkkZyLufLKgcl4GtPmbfDT/L6Rhfn7B4Kx5SZ2fVcxSceA==",
        expected_client_proof: "QNQMidY1CgxG+RF9GfBc84Kj6insgQtkX3SYBUFFeQTA5FHLK1D+DHxFghUfMB1u1D4uBCqVzDGG0qTvb5RBwJg/CCdSeEXmAYN+pkjLgMoxmkb1PefznHHd3FGn5POCO/7KiBnHI2s4pV6iaayxAsD+YVUhv5cxhgKd9UgP0yUXV2JVXjzVf8MplxRe/D+oDIMxw0qZxmAC1wfAfssAGq9a5FB0NgIXZ7RMeFIskHz4yGtKGn2tne1ozN/UECOpx2SxmbeZhCfkoQWbWPtCymcIftu5Hy6EiB38GQBvkpDQ9NeQd5YRuX5ycM8CBjl1af2LJhCz15OhvJEXZTDn1Q==",
        expected_server_proof: "x+hNfi587HOwfxMSA9cErn9i8XXe8WTTvk5ShDIXYqV0MakhC9aeaGiAZOhJNBYkHyKEBpsbEaPD01iWi0BynCmytDfbkeRsyvvtnkPjXRNAV6bfeUzKpSGUFbNClk7okyv02XKQny2LqnzyxGri13GEEjtxUVb/ML2u1MQYJeanRz6qp4YCfWLys6VF0v68I4XEuHSJs/OdAM0ZtfgHSAo7mAxMvQM/lNxe/yveqcGUkufkRtW6EnHbRiOwkNNpDo72D7z89a7/jsU48V3PlV6Uu2Flzx8cdRgZ6BV6VO9unZpN7PFUWx+15k8dCyWwOR9H0Y0W/LCVayYmP75xGg==",
    }
];

#[cfg(feature = "pgpinternal")]
const TEST_VERIFIER_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

y6TtufhYg2mIeauZYOti+GPbd/0vP66kP34TgE6elK/kXkTW/Yfrp1jMmtLiWWSq5cszTMRIEighuwPbZ/z3RrWPxsOg0+jYgbFu8yZ8vOAwrPtLxZl94x0PFTAZBrVapmCn+VYcM+UXdO9v70xFDLwj34tpPbvpODHVWHSlGlhOwndWg3XBE2D9PJopFZajNZiqOScBXree5rDgzU5BBaPbIb6nySpyaeThMCcNzpcEqE8r3ro+E/VdXBvSSJpusr1dvAwHc3IDGUzAhodqV5mjYy9nXwq/9gHWpYNtm76Ols7ReWAhZwy1+cQllQZwGfzzOVGpc+3WutOntQjM6Q==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9a
yywqa/2W9Qyg5MJaNZd2a+0BAPg04gEZI+G8RaoPVh/SYvWx7jpP3L1O8bEi
M/j1cjIO
=5RYw
-----END PGP SIGNATURE-----";

const TEST_VERIFIER_MODULUS_NO_OP: &str = "y6TtufhYg2mIeauZYOti+GPbd/0vP66kP34TgE6elK/kXkTW/Yfrp1jMmtLiWWSq5cszTMRIEighuwPbZ/z3RrWPxsOg0+jYgbFu8yZ8vOAwrPtLxZl94x0PFTAZBrVapmCn+VYcM+UXdO9v70xFDLwj34tpPbvpODHVWHSlGlhOwndWg3XBE2D9PJopFZajNZiqOScBXree5rDgzU5BBaPbIb6nySpyaeThMCcNzpcEqE8r3ro+E/VdXBvSSJpusr1dvAwHc3IDGUzAhodqV5mjYy9nXwq/9gHWpYNtm76Ols7ReWAhZwy1+cQllQZwGfzzOVGpc+3WutOntQjM6Q==";

fn test_srp(srp_test_instances: &SrpInstance) {
    let mut client = SRPAuth::new_with_modulus_verifier(
        &TestNoOpVerifier {},
        srp_test_instances.password,
        srp_test_instances.version,
        srp_test_instances.salt,
        srp_test_instances.modulus,
        srp_test_instances.server_ephemeral,
    )
    .unwrap();
    let mut override_client_secret = [0_u8; TEST_CLIENT_SECRET_LEN];
    BASE_64
        .decode_slice_unchecked(
            srp_test_instances.client_secret,
            &mut override_client_secret,
        )
        .unwrap();
    client.0.override_client_secret = Some(override_client_secret);

    let r: SRPProofB64 = client.generate_proofs().unwrap().into();
    assert_eq!(
        r.client_ephemeral,
        *srp_test_instances.expected_client_ephemeral
    );
    assert_eq!(r.client_proof, *srp_test_instances.expected_client_proof);
    assert!(r.compare_server_proof(srp_test_instances.expected_server_proof));
}

#[test]
fn test_srp_python() {
    for instance in PYTHON_SRP_INSTANCES {
        test_srp(instance);
    }
}

#[test]
fn test_srp_go() {
    for instance in GO_SRP_INSTANCES {
        test_srp(instance);
    }
}

#[test]
fn test_srp_verifier_generate() {
    let password = "123";
    let salt = "SzHkg+YYA/eN1A==";
    let expected_verifier = "j2o8z9G+Xm5t07Y6D7rauq3bNi6v0ZqnM1nWuZHS8PgtQOl4Xgh8LjuzulhX1izaOqeIoW221Z/LDVkrUZzxAXwFdi5LfxMN+RHPJCg0Uk5OcigQHsO1xTMuk3hvoIXO7yIXXs2oCqpBwKNfuhMNjcwVlgjyh5ZC4FzhSV2lwlP7KE1me/USAOfq4FbW7KtDtvxX8fk6hezWIz9X8/bcAHwQkHobqOVTCE81Lg+WL7s4sMed72YHwx5p6S/YGm558zrZmeETv6PuS4MRkQ8vPRrIvmzPEQDUiOXCaqfLkGvBFeCbBjNtBM8AlbWcW8XE+gcb/GwWH8cHinzd4ddh4A==";
    let verifier = SRPAuth::generate_verifier(
        &TestNoOpVerifier {},
        password,
        Some(salt),
        TEST_VERIFIER_MODULUS_NO_OP,
    )
    .expect("verifier generation must succeed");
    let verifier_b64 = SRPVerifierB64::from(verifier);
    assert_eq!(&verifier_b64.verifier, expected_verifier);
    assert_eq!(&verifier_b64.salt, salt);
    assert_eq!(verifier_b64.version, PROTON_SRP_VERSION);
}

#[test]
#[cfg(feature = "pgpinternal")]
fn test_srp_verifier_generate_with_pgp() {
    use crate::PROTON_SRP_VERSION;

    let password = "123";
    let salt = "SzHkg+YYA/eN1A==";
    let expected_verifier = "j2o8z9G+Xm5t07Y6D7rauq3bNi6v0ZqnM1nWuZHS8PgtQOl4Xgh8LjuzulhX1izaOqeIoW221Z/LDVkrUZzxAXwFdi5LfxMN+RHPJCg0Uk5OcigQHsO1xTMuk3hvoIXO7yIXXs2oCqpBwKNfuhMNjcwVlgjyh5ZC4FzhSV2lwlP7KE1me/USAOfq4FbW7KtDtvxX8fk6hezWIz9X8/bcAHwQkHobqOVTCE81Lg+WL7s4sMed72YHwx5p6S/YGm558zrZmeETv6PuS4MRkQ8vPRrIvmzPEQDUiOXCaqfLkGvBFeCbBjNtBM8AlbWcW8XE+gcb/GwWH8cHinzd4ddh4A==";
    let verifier = SRPAuth::generate_verifier_with_pgp(password, Some(salt), TEST_VERIFIER_MODULUS)
        .expect("verifier generation must succeed");
    let verifier_b64 = SRPVerifierB64::from(verifier);
    assert_eq!(&verifier_b64.verifier, expected_verifier);
    assert_eq!(&verifier_b64.salt, salt);
    assert_eq!(verifier_b64.version, PROTON_SRP_VERSION);
}

#[test]
#[cfg(feature = "pgpinternal")]
fn test_srp_verifier_generate_rand_with_pgp() {
    SRPAuth::generate_verifier_with_pgp("123", None, TEST_VERIFIER_MODULUS)
        .expect("verifier generation must succeed");
}

#[test]
fn test_srp_verifier_generate_rand() {
    SRPAuth::generate_verifier(
        &TestNoOpVerifier {},
        "123",
        None,
        TEST_VERIFIER_MODULUS_NO_OP,
    )
    .expect("verifier generation must succeed");
}

#[test]
fn test_srp_round_trip() {
    const PASSWORD: &str = "password";
    let client_verifier: SRPVerifierB64 = SRPAuth::generate_verifier(
        &TestNoOpVerifier {},
        PASSWORD,
        None,
        TEST_VERIFIER_MODULUS_NO_OP,
    )
    .expect("verifier generation must succeed")
    .into();

    // Start dummy login with the verifier from the client above
    let server_client_verifier = ServerClientVerifier::try_from(&client_verifier).expect("failed");
    let mut server = ServerInteraction::new_with_modulus_extractor(
        &TestNoOpVerifier {},
        TEST_VERIFIER_MODULUS_NO_OP,
        &server_client_verifier,
    )
    .expect("verifier generation failed");
    let server_challenge = server.generate_challenge();

    // Client login
    let client = SRPAuth::new(
        &TestNoOpVerifier {},
        PASSWORD,
        4,
        &client_verifier.salt,
        TEST_VERIFIER_MODULUS_NO_OP,
        &server_challenge.encode_b64(),
    )
    .expect("client auth failed");

    let proof = client
        .generate_proofs()
        .expect("client failed to generate a proof");

    // Server verification
    let server_client_proof = ServerClientProof::from(&proof);
    let server_proof = server
        .verify_proof(&server_client_proof)
        .expect("server side verification failed");

    // Client verification
    assert!(proof.compare_server_proof(server_proof.as_ref()));
}

#[test]
fn test_srp_round_trip_with_restore() {
    const PASSWORD: &str = "password";
    let client_verifier: SRPVerifierB64 = SRPAuth::generate_verifier(
        &TestNoOpVerifier {},
        PASSWORD,
        None,
        TEST_VERIFIER_MODULUS_NO_OP,
    )
    .expect("verifier generation must succeed")
    .into();

    let server_modulus = RawSRPModulus::new(TEST_VERIFIER_MODULUS_NO_OP).unwrap();

    // Start dummy login with the verifier from the client above
    let server_client_verifier = ServerClientVerifier::try_from(&client_verifier).expect("failed");
    let mut server = ServerInteraction::new(&server_modulus, &server_client_verifier)
        .expect("verifier generation failed");
    let server_challenge = server.generate_challenge();

    // Client login
    let client = SRPAuth::new(
        &TestNoOpVerifier {},
        PASSWORD,
        4,
        &client_verifier.salt,
        TEST_VERIFIER_MODULUS_NO_OP,
        &server_challenge.encode_b64(),
    )
    .expect("client auth failed");

    let proof = client
        .generate_proofs()
        .expect("client failed to generate a proof");

    let server_state = server.state();

    // Server verification with restored server from the state;
    let mut server_restored =
        ServerInteraction::restore(&server_modulus, &server_client_verifier, &server_state)
            .expect("restoring server failed");
    let server_client_proof = ServerClientProof::from(&proof);
    let server_proof = server_restored
        .verify_proof(&server_client_proof)
        .expect("server side verification failed");

    // Client verification
    assert!(proof.compare_server_proof(server_proof.as_ref()));
}
