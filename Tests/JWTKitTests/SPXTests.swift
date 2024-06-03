import JWTKit
import XCTest

final class SPXTests: XCTestCase {
    func testSPXSigner() async throws {
        let privateKey = SPX.PrivateKey()
        let keyCollection = await JWTKeyCollection().addSPX(key: privateKey)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testSPXPEM() async throws {
        let seed: [UInt8] = Array("0123456789abcdef0123456789abcdef0123456789abcdef".utf8)

        let privateKey = try SPX.PrivateKey(seed: seed)

        let keyCollection = await JWTKeyCollection()
            .addSPX(key: privateKey, kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testVerifyOutsideToken() async throws {
        let seed: [UInt8] = Array("0123456789abcdef0123456789abcdef0123456789abcdef".utf8)
        let key = try SPX.PrivateKey(seed: seed)

        let keyCollection = await JWTKeyCollection()
            .addSPX(key: key)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        try await XCTAssertEqualAsync(await keyCollection.verify(outsideToken, as: TestPayload.self), payload)
    }

    let spx128sPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    Jyl8Ef+FbvH9voZx/Y0kM+VNs3SNYw/PqLX47eN5haokJW+Qx/7+5KAevFwGhDGR
    Q8DmXAf+gNKuOxQHmEOcMg==
    -----END PRIVATE KEY-----
    """

    let spx128sPublicKey = """
    -----BEGIN PUBLIC KEY-----
    JCVvkMf+/uSgHrxcBoQxkUPA5lwH/oDSrjsUB5hDnDI=
    -----END PUBLIC KEY-----
    """

    let outsideToken = """
    eyJhbGciOiAiU1BISU5DUysxMjhzIiwgInR5cCI6ICJKV1QifQ.eyJzdWIiOiAidmFwb3IiLCAibmFtZSI6ICJGb28iLCAiYWRtaW4iOiBmYWxzZSwgImV4cCI6IDIwMDAwMDAwMDB9.3R6Y3nViEjY1Rm-bnwNG0KgY-ET_29M7OC2xmU_AwaDkEB0riVOUcSZToetdhINu_nVIE6MpWglpRTlbxUxUU6SlJrDem8ufv_tugsgGzcUL2rC3E11xie8PlLTgbVkdiWaoKEd75DGafnB1vblUd1UfWZp7bf3lTciJZbWvjTyvhFb6aNrY1zxXU5eEm1zAZxpleKgOyvMovHPb7zy6S7tmD1au-JKQBQTekAQgFmBlnXkAH9K05dvUcVzWDsq-BfyJGdMFgOZTkCrj6gib4jzhHAL8qVs9FpIRKkeNA8vVAmT2K_sTGo-0h5lr29gi0jI1xsPt6Z8bsmrUB47WKJcm756LP6o43Cx0IbVmPdQUfUHIVQxqNG0t_AyUzdRk9N15eXWDBWSfaEGhkgu65kOMW27he9lxPsq25g6ZGpv7gWRZy-msccUesVdwq5Lm7m4kXVHWGmrsKLkc_a51cWlcrY6A0y9CfEAmgwKjVXoGa7jhQzAgFnQjUqSaohC2JZzMl827mNfuNWwVNtRZe2peP8Af0a18LlHlmTUpnfZkMLmd4yTk2RsVxRHQtdytR8-ZgdhK-m5CAlw-2mi3bSDpgw_tO99efZkCe0OTdP-dCzTdybj5x7k1Bqa-4vflmGP4v5d7T13P6LuCowvuQbVTHrGOF0HcE7lLYBpZcbzKhBBZGokXmbfo0dBS1MjoXpwsevx0802LTNdljac9wg1GRb6jHbIgmFl9gISrjN7DQBYGnzcG-hAgr2jUQTEZI0rIBFZRzDptKwVahn1oFkHUn2ec-wn-2kdgpmJnAy_TVLLU3N_gJ-Bjuot-UCeNk7Be9JSs4Q-q1-63E7_1RNJ7BdD_pPVVlGPgv1IC22MiSfhOX5NgwU4oEHH-596xvqLkY0vTC9PDUCkw0uZGuwoDWHy9X-gVJxwJiNT-OajP4R9fuxmDBFFwLIHJ0bl0hz3R1RBOyDS-5q6KXPR-UKAzXbvxvfcAyze36V3o1AY9wJsJ2hNmHCeXlIVWMiZsBWYzsXcE8hb7xRKpUZD5_NOsUjh8ahRP_8ApdcOys-17UBS5Ru0pEyjSSGYwKQExMgkKj6iHQqGpJFY0u-lYUNKQqB3GxkYRshcwN9U8MfTclmy8bX2g2Ki16ybux1NdhyuHleRBdLpYbndSRzJ0cmNQNK_0lfPUN3sLoO6yTFtbpyUMEjh3Yea5jh2X0u79SGY2IaGkJZ1jvrKJ6YthXxQB0zeDKBk8SGlCyp5LgAYV8VRknmT0tve-09UCsX4c1xeVjvUG31LwEp6_A4-6mGVmXFD2lvBvSIuKaSBFOHX_wBqwqlNFDlwAe0KJJVlB-9yJHL-PETis0WpRWvYKjyW2bNpIaMGrMSUVyIdfSwIrQjw-1D-4xbws_WxMdDTbBTT6PfFwUET-wOfmq0794lfpU5cE3PTBj-vDbR1wHW06xU-Pta24QTAzmQfYcQbbeYJRGD0g_u9BUASz8wIYneteCbO-vq7snfQMgNpQVEIHURTvOn8SfuD_4tX0qRvQPQtyM0VldOCbsy7bf1r_c_ZI2BTuELNTIjXgY1do6LhphBGCp52ekfXMvgmC8RD62Pau9AKWZUY_MOuGBRvaWIyvNSKCYngL0CWytirPgMLUfLvk2j2h8qtBzCEpMzMOHnLsGRlJ-XQ_iyfn0vAtcLQlMftr1HNpJNkXEbWjIkbOJDrZOZaUfhmqiC4VnFYLgzz5PtpaGk-YfugiFGBSKGVWy239iSihKeR9o3yrD2NC9WwyEXhav1UZZvlVsCM0SoiCh2sS1a_PYzQwkwDfzRADcnqxfU2wT1zw-UAC4uL0NGSQXES6yO3oFBpLFFPbIofG_e1gYodqR8HcGzX6itE8DmeBY7DvsINpQEnyqd1NJvjPA3WsCytOFv8sa3Dss93CrNn6Oh4uZplnZ7H_70PvaMB7m1-l6AVWi6U9gsAjccHPxL_971K22XiQonDJqV0e-HgTTCLnrnjxqQTkP-awMd4an0lzporobXtzr_GSHJPcUSaOuR8nHA-WbVyTfVOFGsyaXoWuzkuSXbbVPPCxolIrX7D7iIcirxyv6BRUMUJ5aJ626t-9LHmk_1bzjDh5bgoUA4qtkup4pv0xWGdThJlOjdoPj9pCBf_5hcLd859f4idap-6Q0FMtWgjUoN5PXYg-dGgSYAl01EO2T6JyIa5bVF1LVs5E8UkfqVxxtm9snZJ10_Fs8PboqrBpnff8Zc2CrBv-uiee3uwMzBR0aVQ00akmjBBQ1UPTisj6M1iWfjblRuQ8ri2RnWZlZl_7s5wYGs2d6-F-SEMBwjS4970np_uSs4MpH0rXyWFKbpWlnbcRVn9RbmBcP5jfLJGaJ8aAMGuZ2yOZQxIyaZw72JJBHLgrKSDvB--HU0V54oVHsLCEyj0WdTa0AbC5-VdRL8K4szq95cVM2teyiCKvS9TYoDopNaEDnRlsenoyvoxuJvBK71lLJPhKY2lgzgukEPgCUuVjYJgALIN37a0VMaJ-q_77IoMjkCZ5UXAQmSNh4X_t1hbvnPm01SacklOA564VjSfTKXkriCtnDrYxwuG0CTRgNPNOJhXR7VvCsif4bUanVAnYVVf99OK4RAa4c7JSJK6AnUJ1D-6O4cQb8_GupqZkhXPXE6epM0bn4VHGlPU9TwckosL3Zj7VxOVkSn1g3FHJ73D_suOaQuV0nMa9Y6GzVCHO-l0COHZTaNEwuNF5OF6-oDt_paBXWlPdDact5-AK1irPX5JFMPLPaYGRKmTX0HOMN6jL4Wp3ioIoDFjf-Pz__DEZOEsoOHmMVLCfrLTJU8ngyQbPdIQWPt5ML26pfsbs8IPysM5CCcpmsP_y0Wb9zGJMwLmgWidjtVodvka7XTisNGI3QI6aFtIzD0ZYyIXAPy_MqEOUQeWKCJyMrvjcIDBfIBWUpzrjvV3jxU7Qw4Yok8F_R1wRr2afXJIvKB6oW2kTEyUeXkQ3zzSA0HNRWttlTFr-UqPYSfWj6b6w02374I181s5uV9EjvfzedQI9az4Vqy2ZqnfEqBWxAc3OvUObyFxcgQx45udPWZFKxvK1kSjw4OPvmMLAES2Xnd5XnJCkPBeN1U5AXF4kQWQnBOgdWiSeJRljk876aO5nUXMYhI3rVOKY_1p2HYobhQj2cQeIvXUrZicj6b4fP_xOpJz40i9Iai-4XLJBOgZRq949ZhOKHRgbRvM1jEIFKi7DgCjoqBsJpyZIMH2MquWd0mprqm5LxsFkSNwiRpMUBTKDlDhbTDY5DJOKVd-uefUxrVv0MWBMpJllG0uw4f_hI6T96ixIStxbHOEBpG5pUdZ2s8SgCoJy1ha6lPvYNaoqpTCimBf_Fe257-aq5XLNWWZxsSUrBXMUMTatBmQDMh9fVum4aLNPLvgjrHw-TZPg7-ze1EuG7kAMVyURJgRMJdSCGf6ja0SVDgJORIRrNvUHlqOt9wcSTToyUT45NvVg9LiUE8qDrF6b8R8gb685Uxo2joqHyYishD2Tpwq70ufqi-avj0tC7_WlRLA1FjKXnNzdvx-NE0fVuiF2HKN2ZU6JWoRRPclEwlEEzFfTlXpl5-YoON6jU9a2K91neFbNAW1rfVZAY6AAbZgrD1r3eanBP6-oot0lpHCGqh9NsplW9h1cwxonKnUweMCUbSsQZ5JfJJ4FJrKZXnIe2r-fbN1AIBTTMtrhREHOxhzS09rh_hflu_EGl8AfC4COlySJLPgL9E9I0Czp0kXqFHOBPFe3D6ll452mMTDYewDGoykxoKWslKk5H4ttVX3wX-Xn1GbU9WsJKU-TRJ0WwgYejHEHGxgqC13hCYI4e8S0CPyYTiovDBP48J5TsK-TyW82K76eR49cGD-cpT3HSRiQhD3MthcAeymfNGPZkNiB5gL-AUkHAduypYDNb0C7dcWMXyBrOW9ubnxoORSPLZZemVrCvrHb8x466zmphHzFF9wBgRn8FVqfjNuans5OAko58UHBDbyYaGViVwj9C-b6xTmFxrXtAGsWeMySm4rbJYHBJSHyZWJmR6rD48fgMKsCg_3XiTPIFI7_kbC3KWt4jHRdA_tkLBGN8tpTS5LilUEmeN0LSoajqPPjRDuPxM9lpc-O0gPrvsUtOA8yVX5-EHT3HiHiX9KIrI0VvHD5guRRgmtY-SLRDOoiyxG8qREznOXb6qBIEouR7CZ3zcIWgAZ_i3MnVisL6MDrSrbcj396-p0jXrguem42uTN0Wx2H8Ji7Gv3KEUift9R3DTPHwoblyeZZniP5He2BdefJl2VvPam_zbB_-Mi58TzG9SCSsO7o9fJ4HgdvYd-io83e32t2a5vUhPk4TnSBFvDbCckoH19vr6ea2yUSkr8VCludUSTlq0e9gIIy260sOvhOOWaQ-bp--Z6_htbwzovlwlFFEnaSwduv1RdVtrI0gM0soLiWJHv67I-0PxCGKtKhiXpOc0TUNURooiXHrpZQLrkyjx1hw_cIO18rAzX_0ygCLVcjjR2Lr0iwJo4g3n5O0K9uLLU2sd1SwxMdptRGvW9XHJ-iwlG_G7ACsQIMYUaXfFF1xbY8CbkVcWC2NertDn7VoERDM45G2A2HzfKmoUMbLjntujJRwmcg-y4n1G0VoeJ0pS-l0CvPN5W7QhGjSLRy9U6K4Ri3Ejten1Dk6d1qzOR7-5t2icf9SAyHiHeatZgdarCvwSRaDWf7VniBvkfVEQbNr0YhYjuLI8s-MuGMT4Y2iUzHRAqFmzGVqu-iIMPxKnBZUp5wv_Ib9SnxxI_CFcqugz8pAaw_wSW8k2T0bMq6dM4CClaAJx-g8KAWI3P1K-n5MOpDGgehqroD5LjdQZq9k0Rq1SeJJ3xWDTZVtKjl2gpZKYMTZMX0GU3jm8Awx7Ul3SpRGr58pDPA9UWxl_wQVdDhsKAsmxpONS5AyveIeSVinEB44lvYIhgHf5eGnilqPwFBuKG_cuuvRHEaA_5Pnq8atkZbBPnjsyBk0ba5HU2q0c5543NVoyUAJhYOi0t8RF82RukGu6qVz3cH99p-8rTVbCtkZ78nhzz9Tzm3exyicwUps6r5LUiWsNgl0TAlx1EmNaZ8Ty3Z_hmmAryWN979Qbi1eUcY1t05Px4WSJV-NA8hGIwJQ6b6sDOHUO0bQD-32BRIf7DlPrxw-s2Y6C_QFIjAzWdQ4tdIFBCQTEM65uBCNw6JRGm_5yY2diyy7R9aivgXKlrP5rZyylDJM-p_dJnykQ858_I84eTuKjiSF-vKtBN3-r963yS6qy6RZQJxOT8FVozhq9vrMepYt5_lvu4dMqLYJPs3Ras0d2NjNaaAYCUwadwjy34xcr0eFeQQUrxnj5XJpjqmJgVioj2cnPi4E-QcftBvcTLrmP2CIdU0FUlPYwSQMc5KiWsXU8p_RqrITkaQZDlISuV1q8P_UudIi6i7H-QyOYMASH2g1dm4mBcQ8KWMvUQU8-EVA-PZ5mGRoyPP-qmZgG19qGIdmksiRGHUByyUOepY6GmP3mIFGjvY41biOtA029tFz06Q1htIgYJl7NT2o8VIjx1Hu-Jm2ZfwwHDqFoVqvV_JaSjXCHYXn2zLolTGZXynGK8_p8QUPZ0YRQDP_dNnfmn95urvP-Be3jiCg_3V87nevYxe0PseCZiIFIBqF28m3NDKuGRF49OmPd5g6rFoIaYBF8j6Sis3eHSA4-brZJSUugQPWxYW7oJZNW1Cjx3LjDmUC4-am6nJJK-OpFBasVS8-x2nBC5fYrACBK4mPen2LB2ONHKq98bttGoGqVrjI5zFWN3TqzVrYgVEwD1X-d7N_ZK-ziR1L0yxe3R_Fpxs1OJ72r-hnhtVWWrVIn0Ud-jSDK3CJBZ2RYFYirh82fg4ELRYkvZE0Sg24KfOxlkCWVDIa5sKC4bME_q_b1_J8JAwvNSEzWL96kha_TCHh89MWwy0fcN2E4mIvaxUmu4L_I2XbJv_uFo0SkvtjTOTicyonWdoUMs2P9Ec_nF6PZ-XwjAOZiFvuoVkHpnYCZX72VhD78jIE3uN-RvwkaYU9323ZwBH_u1LjM8hB2U61gP7EaeTfTZM2YrGbSEzpNoPAvqXDqAEkeNeHh8HUbgJ_RLUpi--3mjh18-8QOCP24QZ-MqS4EO8ueKB9hI-si9yI5AtPmZ6gg9e552bpvx1ox-MI_J1HRefvQXPm1OPopWiyb1M56kvMCcUt9qbI4RkFa2wmIGAHDhG3yqpNLwhlSCSxuBM9mhTtXlB2dp3N8qqj5LmiYGraZ8jokWDJr557BObiNWKAnzhxWdeY4EWx7px0s1tHHwHi1JFNdNBq4iVequva6tbr6x27_-wgkLIgl1avMCmYudSovG23QM3WQMOH9pDdjRUK4B6dw0LsedxBnsJworzbaQ-gVsz-noJ374TARA3cXFv8FRscNhEg8Oox1c7LAT7niRQxCFHQigXu6NziICSwgKQjRhTxOCHUM-HJB8InFT35Y4ahgTsDwOU3qUB5wPd82zP4NlpLOpxrNtrISzRnxf56fVXsTUNS3XKykf6npcQTReL7e9D7kBqWt77EbhUBSw67IxJenBi89zrnf0h4PBQz7GWX-2vlnHVLf0XGtS6Z6HLJvnGVr3MxNk_HH9aqetPcYCJx4M8ONTXylyJHPZAt7Gf80CPimgFaVN8KTh0e05myX0TvqcABjD_XiYVIJMxj8aEo-hsEpbsI5MOr4XoG4RwbMrd9FhYZDG43NpBc3sg8WxKy2ui1jpCK0w6GVGW00-87IQZB31OKbF55axY3tGepqTmr2rl0QaZNdnMo_s6iudkn5HCqcDlNDZdKQqlZ4bpe4L-d0ZxW57owE0pQDTS2mPf54CcT3Iqr9FYDLwHWMiwHPx4Vp8cLN1E0SQ4kqHdXDvMwO-gXCr7iBWPAb6pfWEKRFfhZLammhHHRAFmvLhWjRP8q6iH-aB0SMi7u7GG_lh7G7rhB2Y3IIcBQ371YcExbNTXZ_eZp5sZLwzWtb8ICi2uJah5kUEaKyXQPtdcLQ4eG6VEIPJMNGTq9WBg8luIUzFTJvEvg5A5eE3dX8uxjqtX8GNK_BxB2rBU387hK6LJYL7NWAHX8IEraTcxjco1Ywo8xgVr9GLTKyfVX-Kw_2YYHz4ZV-Ique1BWReF6ydCaDLNkAYcaxHG0N4swq9fQAqhx9YDFZtIBy1CznCz6oUtCdG4JnBqX8bGZJ-U1JGV5AROU7dfLE8h8Ifio_XH3HCmN0IZ5_ErPv9ZQZS8437rop5s8OXXVzIbeZP7AbrU_HtqsmJf0YyWZgPhdXxWE-UfQ1p_WTzsUd_AXAU-6eUXgEwLGr3JlMoPgCYBZ3NQtkiyh0txDBI4kxgQ4_uzhlCh9FpQcW7p7B-JjL9_vapH7kJzI1F91FVFXyU5jF8jxwcgPStHAUVfwfLAs9wZIkmKZCQ2hfp-N0PHBYes6VNElo3YDtutC160kXiEQnhrXwctihCNgbKqjSLkqH5oZTccu3LoJeVnynur26s2TMQs8ng_ndMAf4L9u0jj8RtaKF_IFEEvBD6eBtyn48tazES55rdYy7HjE0RCjTUdVS7xXIONc0ixKB3gsxgXJlj4EbKSghGOc-CXYOfpEwYMjP-54EFEkK_AW615sEPBNZnvBaDXVh97Ezzy1IGnqjTWBnMUy3yza4lSYl5upR4T-Y-bCj_FEsyuU1Ofu6-MVKci64H5K0OTvMM8RWvlsjONpv59gX09X6MWMuyTNaCf6N56n1P4p0uxjaagLM1LQVg7T__2m_a8otfU0IM6RuVh4RO7-mHlrlU3jaGFzw8HVOWV04Q32uxVd0U1FTEOqIu3LDnEFUeAfteB2DKsRxHe1wYEHeJ0fnZFRgVe11chHPG8PzUs9833WlCFXPDImu7UEoi_5Wn-y8nu6fqas1eScZVmfKiP40muUy4PkaAdCiTxxQACFOn8qt4VlRBtpSkbdFZraxPNLwj8UXUesAXcz7m8uWxrcACgh1g_4q_j9LTvV7ECmDLkOM4y5xO1c6LbTYzBo_GMpZxK9FHuQ1EiCJvuuL3EWfdqF7u_isPi80P-Rf8mRjrUgx_U_7y8zZu8QFyecEvptidcll_-CXcRckSmGTc1b016jM6-8pXcsCRiyjnVnM7qjRgY75MMSteOYvZoaUj1IbIAPaK4I_Lk4afUJF-EinPvzFcsDhr8fIe-A9vBEZAXqy3cEexVMq7DimCrUd27ldFq6x8DDRyLBr1egHlqbN-Y61k20FV0zoWFqjBLootuOWxbDxkIHx49RXa8_ocKU_Hjhd7kEETK5GRxj6PT2hg5wVlpTuv05X6Hn33y3-pgkMAwC6RdTlnqfcZR66qWInd6xZo1tI0tNfDhD2wFobDgi0qqZCGKTj8oAxiQUy7uZ0B8PESlC9RVBulsBXY4CLunD9IKbC3WBssTvmoYo59HDYULKddqWlhONQgkqvWf7X1X04Rp4ObWWNluM0ZcwbIsCsIGqk2zfLiDvBG9ln4SDa9WnuxZHiRilJUbUTtEGXaLjGqgLgsEGmSdScG3UX3Rm4PQFX-uMu-E6NL6z5juprAmUTwzYSYtly69kCejHaUPv5vLRv5mf7g0Ns3q2E6zAcMySrhhDogfqobPHyTCRc6vnxkpddGvemMGGf27RxUUuQrJ43P0tSHdmZAQ17dI_EljDkMv3n-YOPIv08J5TpoIhlELtMsfpcA3I5OASwWzkBBrZuO4l6gBRURMMXdKwDOe7tVWNF7Mb5QzwY_nvO0lgBRWxVJsBloAk4IdxseocCtFrw__icK-uD7SNhB9MKR-DUpKinTgNby5s6pl_U3ntLf5i246WiC5DW8KUx-3L5yNp4AfqsSaxOqQJ1qdNZd4H020N0ZuTUt8urbtFVkwbD_TIGsn2gaPSOsY1j5KBwCBktLaPIlQYMFwgDgBq9AurgOzVhjU6vUjTLxv9At7v8MjRBHighmHLwH_l-zKX8BsLs_cyrpYhf7AHjGj7MYnsBKuJ5YnEcir3s-3XutB7qwiIhGaVFXjBIH1hpPYEmY9so0cVneJuONVWlAP0Nvrv8E9Bf15r8pc8ygFN_KirOChawMXl7iGi0nzNemnjG-7O8rgW22Jen9Tlvk9H0R_aZjdSIcnrb7Tra5JCvuAzC3kebRPXRxAmFkvdG6QrDzHS2JnlsfkNR2vYrUe8Xn3LuwNIx5Mz32_NP0M996sMMTDDxAgc00d9JEko-2-lyh6dgPbZk8l90roCVCa2lC4uLGtIl1kh8iZ1yNR1IPQusE-BONa3Py_TVrUuPS8LiyheKTJs-FlZlEH38TrIExjB3GetMU8uzQZypXSKl7Pi0OwtGOrLcw7ROermPTyX2pmpi50NJidvJz9Kgmi_pKK7v4yrjFIHtvaMu1_RT8j1t4WDelOFwys300V5YUel_2nlyeVkPN1hSo40sEev10RDGUNI3P6n2Tizz9z4lVE6Ihh8HoPlsWJWnkChahNbw0vGLl3rBNAjKM5iou8Pe36qjviKL1limstrLsf3uUG6CXjqZ_CDW8uLXSLTcnWXiVXUkWwQNdi0bySBc-AOXHvrYXAVmm6jQP1_PtiB0teG55WT5W8I24woDjtjapottPmC0cmvFjheVoPKEyP_UWzEniuU2CrPNySes1MQAG6zps669Oguz4lCLXJ2ezQAKOMzYMV9an9pt_QPLDUwLhtmwBtUa-61svgQIa_0ptqyxjowFy5D6DXMk1Dgvm3i521Ow2IAtwVZO3sHRRTL97zpW7636ABaNo-RVYZe-bXXLdpRaVpes0ItADNThVBCcQkO1MDtNoS7U0sqyBEPX0zEq3ViQ132vzkyShSkxOy-b107KriuJ4eu9J640QFX1gff1u4ij68b4ainm_TWlR8RdGmTUngUwOvl0rKepUGFbc9r4Rlsw1ldJh5kr5UzOO8eakCzbCp0ITqb6ZqgaAPxEx0aa4dV0oESPt8CckE1RUGhBwhhTl2Io2UNNXBCYeerpa6-IG6H-22zegGs6u3qeTJo6PmXIyoeJBt-dYOt77pAJQOX4duuvEHSgN9_GcyXkn5JGfu7A_SxKFVp_U-X6vrl-lx0yEPauQEuX4gaFOZzTviX-O6l2ZtPSEQLijXqBkf0WA0qlFrWnkQikqJZZJbkgPSQ78hu4KPpWhkNqVw0aD9MJSuVehna2HcUt5DdunABjOPxrjKcvc6m5QUcWFu9jSQwQN9y9fF1Oadq-SbGqv5GxzlDh-drr7YCi4CAuQ2XbY_PaObRMFtPWZUBrQI34GcMrAKN8n6oYaCXq09C24sNz9SWL5rwA_w12rjbAO6NWnsKVuNNg4pq9wqpsAD4bQyTSc11KiOAHVA567mmMgk8dITJ2P8KNom_3RafI-DCR3kWl06ZFiGOCFeEAwbmNVOWIibnehfFFL7x5CYGE4IptbJqqEf3lNdjcw
    """
}
