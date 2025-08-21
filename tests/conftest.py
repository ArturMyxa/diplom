import pytest
from rest_framework.test import APIClient
from model_bakery import baker


@pytest.fixture
def api_client():
    client = APIClient()
    return client


@pytest.fixture
def user_factory():
    def factory(**kwargs):
        return baker.make('backend.User', **kwargs)

    return factory


@pytest.fixture
def confirm_email_token_factory():
    def factory(**kwargs):
        return baker.make('backend.ConfirmEmailToken', **kwargs)

    return factory


@pytest.fixture
def shop_factory():
    def factory(**kwargs):
        return baker.make('backend.Shop', **kwargs)

    return factory


@pytest.fixture
def order_factory():
    def factory(**kwargs):
        return baker.make('backend.Order', **kwargs)

    return factory


@pytest.fixture
def order_item_factory():
    def factory(**kwargs):
        return baker.make('backend.OrderItem', **kwargs)

    return factory


@pytest.fixture
def product_info_factory():
    def factory(**kwargs):
        return baker.make('backend.ProductInfo', **kwargs)

    return factory


@pytest.fixture
def product_factory():
    def factory(**kwargs):
        return baker.make('backend.Product', **kwargs)

    return factory


@pytest.fixture
def category_factory():
    def factory(**kwargs):
        return baker.make('backend.Category', **kwargs)

    return factory


@pytest.fixture
def contact_factory():
    def factory(**kwargs):
        return baker.make('backend.Contact', **kwargs)

    return factory
