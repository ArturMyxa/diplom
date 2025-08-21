import pytest
from django.urls import reverse
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_201_CREATED, HTTP_403_FORBIDDEN

from backend.models import User

@pytest.mark.django_db
def test_user_create(api_client):
    some_user = {
        "first_name": "Oleg",
        "last_name": "Petrov",
        "email": "olegpetrov@gmail.com",
        "password": "13656vbvffvf",
        "company": "Google",
        "position": "Engineer"
    }

    url = reverse("backend:user-register")
    resp = api_client.post(url, data=some_user, format='json')

    assert resp.status_code == HTTP_201_CREATED
    assert resp.json().get('Status') is True


@pytest.mark.django_db
def test_user_confirm(api_client, user_factory, confirm_email_token_factory):
    user = user_factory()
    tok = confirm_email_token_factory()
    user.confirm_email_tokens.add(tok)
    url = reverse("backend:user-register-confirm")
    resp = api_client.post(url, data={"email": user.email, "token": "wrong_key"})
    assert resp.status_code == HTTP_200_OK
    assert resp.json().get('Status') is False
    resp = api_client.post(url, data={"email": user.email, "token": tok.key})
    assert resp.status_code == HTTP_200_OK
    assert resp.json().get('Status') is True


@pytest.mark.django_db
def test_user_login(api_client, user_factory):
    mail = "test@gmail.com"
    passw = "cdjndcbdbcdh12345"

    some_user = {
        "first_name": "testfirstname",
        "last_name": "testlastname",
        "email": mail,
        "password": passw,
        "company": "Yandex",
        "position": "Specialist"
    }

    url = reverse("backend:user-register")
    resp = api_client.post(url, data=some_user)
    assert resp.json().get('Status') is True

    user = User.objects.get(email=mail)
    user.is_active = True
    user.save()

    url = reverse("backend:user-login")
    resp = api_client.post(url, data={"email": mail, "password": passw})
    assert resp.status_code == HTTP_200_OK
    assert resp.json().get('Status') is True


@pytest.mark.django_db
def test_user_details(api_client, user_factory):
    url = reverse("backend:user-details")
    user = user_factory()
    api_client.force_authenticate(user=user)
    resp = api_client.get(url)
    assert resp.status_code == HTTP_200_OK
    resp = api_client.post(url, data={
        "first_name": "Igor",
        "last_name": "Pikov",
        "email": "igor24@mail.ru",
        "password": "fjsldkfjlksd",
        "company": "Company1",
        "position": "Position1"
    })
    assert resp.status_code == HTTP_200_OK

@pytest.mark.django_db
def test_user_contacts(api_client, user_factory):
    url = reverse("backend:user-contact")
    user = user_factory()
    api_client.force_authenticate(user=user)
    contact = { "country": "Russian Federation",
                "region": "Vologodskaya area",
                "city": "Cherepovets",
                "street": "Mira",
                "house": "23",
                "structure": "3",
                "building": "0",
                "apartment": "21",
                "phone": "85-58-87",
                "postal_code": "16262"
                }

    resp = api_client.post(url, data=contact)
    assert resp.status_code == HTTP_201_CREATED
    data = api_client.get(url)
    assert data.json()[0].get('house') == "23"


@pytest.mark.django_db
def test_products(api_client, user_factory, shop_factory, order_factory,
                product_info_factory, product_factory, category_factory):

    url = reverse("backend:shops")
    shop = shop_factory()
    customer = user_factory()
    category = category_factory()
    prod = product_factory(category=category)
    prod_info = product_info_factory(product=prod, shop=shop)
    api_client.force_authenticate(user=customer)
    shop_id = shop.id
    category_id = category.id
    resp = api_client.get(url, shop_id=shop.id, category_id=category.id)
    assert resp.status_code == HTTP_200_OK
    assert resp.json().get('results')[0]['id'] == 1


@pytest.mark.django_db
def test_category_get(api_client, category_factory):
    url = reverse('backend:categories')
    category_factory(_quantity=4)
    response = api_client.get(url)
    assert response.status_code == 200
    assert len(response.data) == 4
