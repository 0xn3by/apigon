def single_bola_test(client_a, client_b, create_res, fetch_res):
    b_create_res = create_res(client_b)
    target_id = b_create_res.json()["id"]

    a_fetch_res = fetch_res(client_a, target_id)

    bola_check = False
    if a_fetch_res.status_code == 200:
        try:
            bola_check = a_fetch_res.json().get("id") == target_id
        except ValueError:
            bola_check = False
    return {
        "target_id": target_id,
        "create_status": b_create_res.status_code,
        "attack_status": a_fetch_res.status_code,
        "is_vulnerable": got_b_obj,
    }

