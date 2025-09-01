import json
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from django.views.generic import TemplateView
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView, get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from ujson import loads as load_json
from rest_framework.viewsets import ModelViewSet
from backend.models import Shop, Category, ProductInfo, Order, OrderItem, Contact, ConfirmEmailToken
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer
from backend.tasks import send_email, get_import

# Функция strtobool для Python 3.12+
def strtobool(val):
    val = str(val).lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError(f"Invalid truth value: {val}")

# ----------------- Views -----------------

class HomeView(TemplateView):
    template_name = 'home.html'


class RegisterUser(APIView):
    """Регистрация покупателей"""

    def post(self, request, *args, **kwargs):
        required_fields = {'first_name', 'last_name', 'email', 'password', 'company', 'position'}
        if required_fields.issubset(request.data):
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                return JsonResponse({'Status': False, 'Errors': {'password': list(password_error)}},
                                    status=status.HTTP_403_FORBIDDEN)
            
            user_serializer = UserSerializer(data=request.data)
            if user_serializer.is_valid():
                user = user_serializer.save()
                user.set_password(request.data['password'])
                user.save()
                token, _ = ConfirmEmailToken.objects.get_or_create(user_id=user.id)
                send_email.delay('Confirmation of registration', f'Your confirmation token {token.key}', user.email)
                return JsonResponse({'Status': True, 'Token for email confirmation': token.key},
                                    status=status.HTTP_201_CREATED)
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors},
                                status=status.HTTP_403_FORBIDDEN)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


class ConfirmUser(APIView):
    """Подтверждение почтового адреса"""

    def post(self, request, *args, **kwargs):
        if {'email', 'token'}.issubset(request.data):
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            return JsonResponse({'Status': False, 'Errors': 'The token or email is incorrectly specified'})

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'})


class LoginUser(APIView):
    """Авторизация пользователей"""

    def post(self, request, *args, **kwargs):
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])
            if user and user.is_active:
                token, _ = Token.objects.get_or_create(user=user)
                return JsonResponse({'Status': True, 'Token': token.key})
            return JsonResponse({'Status': False, 'Errors': 'Failed to authorize'}, status=status.HTTP_403_FORBIDDEN)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


class UserDetails(APIView):
    """Работа с данными пользователя"""

    def get(self, request, *args, **kwargs):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                return JsonResponse({'Status': False, 'Errors': {'password': list(password_error)}},
                                    status=status.HTTP_400_BAD_REQUEST)
            request.user.set_password(request.data['password'])

        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True}, status=status.HTTP_200_OK)
        return JsonResponse({'Status': False, 'Errors': user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class CategoryView(ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(ModelViewSet):
    queryset = ProductInfo.objects.all()
    serializer_class = ProductInfoSerializer
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query &= Q(shop_id=shop_id)
        if category_id:
            query &= Q(product__category_id=category_id)

        queryset = ProductInfo.objects.filter(query).select_related(
            'shop', 'product__category'
        ).prefetch_related(
            'product_parameters__parameter'
        ).distinct()
        serializer = ProductInfoSerializer(queryset, many=True)
        return Response(serializer.data)


class BasketView(APIView):
    """Работа с корзиной пользователя"""

    def get(self, request, *args, **kwargs):
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket'
        ).prefetch_related(
            'ordered_items__product_info__product_parameters__parameter'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()
        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        items = request.data.get('items')
        if not items:
            return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                                status=status.HTTP_400_BAD_REQUEST)

        try:
            items_dict = json.dumps(items)
        except ValueError as e:
            return JsonResponse({'Status': False, 'Errors': f'Invalid request format {e}'})

        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        objects_created = 0
        for order_item in load_json(items_dict):
            order_item.update({'order': basket.id})
            serializer = OrderItemSerializer(data=order_item)
            if serializer.is_valid(raise_exception=True):
                try:
                    serializer.save()
                    objects_created += 1
                except IntegrityError as e:
                    return JsonResponse({'Status': False, 'Errors': str(e)})

        return JsonResponse({'Status': True, 'Objects created': objects_created}, status=status.HTTP_201_CREATED)

    def put(self, request, *args, **kwargs):
        items = request.data.get('items')
        if not items:
            return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                                status=status.HTTP_400_BAD_REQUEST)

        try:
            items_dict = json.dumps(items)
        except ValueError as e:
            return JsonResponse({'Status': False, 'Errors': f'Invalid request format {e}'})

        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        objects_updated = 0
        for order_item in json.loads(items_dict):
            if isinstance(order_item['id'], int) and isinstance(order_item['quantity'], int):
                objects_updated += OrderItem.objects.filter(
                    order_id=basket.id,
                    product_info_id=order_item['id']
                ).update(quantity=order_item['quantity'])

        return JsonResponse({'Status': True, 'Objects updated': objects_updated})

    def delete(self, request, *args, **kwargs):
        items = request.data.get('items')
        if not items:
            return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                                status=status.HTTP_400_BAD_REQUEST)

        items_list = items.split(',')
        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        query = Q()
        objects_deleted = False
        for order_item_id in items_list:
            if order_item_id.isdigit():
                query |= Q(order_id=basket.id, id=order_item_id)
                objects_deleted = True

        if objects_deleted:
            deleted_count = OrderItem.objects.filter(query).delete()[0]
            return JsonResponse({'Status': True, 'Objects deleted': deleted_count})
        return JsonResponse({'Status': False, 'Error': 'No valid items to delete'}, status=status.HTTP_400_BAD_REQUEST)


# ----------------- Partner Views -----------------

class PartnerUpdate(APIView):
    """Обновление прайса от поставщика"""

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)

        url = request.data.get('url')
        if url:
            try:
                get_import.delay(request.user.id, url)
            except IntegrityError as e:
                return JsonResponse({'Status': False, 'Errors': f'Integrity Error: {e}'})
            return JsonResponse({'Status': True})
        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


class PartnerState(APIView):
    """Работа со статусом поставщика"""

    def get(self, request, *args, **kwargs):
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)
        serializer = ShopSerializer(request.user.shop)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shop only'}, status=status.HTTP_403_FORBIDDEN)
        state = request.data.get('state')
        if state is not None:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True})
            except ValueError as e:
                return JsonResponse({'Status': False, 'Errors': str(e)})
        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'})


class PartnerOrders(APIView):
    """Получение заказов поставщиками"""

    def get(self, request, *args, **kwargs):
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)

        orders = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id
        ).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()

        send_email.delay('Order status update', 'The order has been processed', request.user.email)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


# ----------------- Contact Views -----------------

class ContactView(APIView):
    """Работа с контактами покупателей"""

    def get(self, request, *args, **kwargs):
        contacts = Contact.objects.filter(user_id=request.user.id)
        serializer = ContactSerializer(contacts, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        required_fields = {'city', 'street', 'phone'}
        if required_fields.issubset(request.data):
            data = request.data.copy()
            data['user'] = request.user.id
            serializer = ContactSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True}, status=status.HTTP_201_CREATED)
            return JsonResponse({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                            status=status.HTTP_401_UNAUTHORIZED)

    def put(self, request, *args, **kwargs):
        if 'id' in request.data:
            try:
                contact = get_object_or_404(Contact, pk=int(request.data["id"]))
            except ValueError:
                return JsonResponse({'Status': False, 'Error': 'Invalid field type ID.'}, status=status.HTTP_400_BAD_REQUEST)
            serializer = ContactSerializer(contact, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True})
            return JsonResponse({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        if 'items' in request.data:
            for item in request.data['items'].split(','):
                try:
                    contact = get_object_or_404(Contact, pk=int(item))
                    contact.delete()
                except ValueError:
                    return JsonResponse({'Status': False, 'Error': 'Invalid argument type (items).'},
                                        status=status.HTTP_400_BAD_REQUEST)
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Error': f'There is no contact with ID {item}'},
                                        status=status.HTTP_400_BAD_REQUEST)
            return JsonResponse({'Status': True})
        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


# ----------------- Order Views -----------------

class OrderView(APIView):
    """Получение и размещение заказов пользователями"""

    def get(self, request, *args, **kwargs):
        orders = Order.objects.filter(user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct().order_by('-date')

        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if {'id', 'contact'}.issubset(request.data):
            if str(request.data['id']).isdigit():
                try:
                    is_updated = Order.objects.filter(
                        user_id=request.user.id, id=request.data['id']
                    ).update(contact_id=request.data['contact'], state='new')
                except IntegrityError as e:
                    return JsonResponse({'Status': False, 'Errors': f'The arguments are incorrectly specified {e}'},
                                        status=status.HTTP_400_BAD_REQUEST)
                if is_updated:
                    send_email.delay('Order status update', 'The order has been formed', request.user.email)
                    return JsonResponse({'Status': True})
        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)
