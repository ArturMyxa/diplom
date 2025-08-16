import json
from distutils.util import strtobool
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

class HomeView(TemplateView):
    template_name = 'home.html'
    
class RegisterUser(APIView):
    """
    Для регистрации покупателей
    """

    def post(self, request, *args, **kwargs):
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(self.request.data):
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {
                    'password': error_array}},
                                status=status.HTTP_403_FORBIDDEN)
            else:
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    token, _ = ConfirmEmailToken.objects.get_or_create(user_id=user.id)
                    send_email.delay('Confirmation of registration', f'Your confirmation token {token.key}',
                                    user.email)
                    return JsonResponse({'Status': True, 'Token for email confirmation': token.key},
                                    status=status.HTTP_201_CREATED)
                else:
                    return JsonResponse({'Status': False,
                                    'Errors': user_serializer.errors},
                                    status=status.HTTP_403_FORBIDDEN)

        return JsonResponse({'Status': False,
                        'Errors': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


class ConfirmUser(APIView):
    """
    Класс для подтверждения почтового адреса
    """

    def post(self, request, *args, **kwargs):
        if {'email', 'token'}.issubset(request.data):
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                    key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'The token or email is incorrectly specified'})

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'})


class LoginUser(APIView):
    """
    Класс для авторизации пользователей
    """

    def post(self, request, *args, **kwargs):

        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({'Status': True, 'Token': token.key})

            return JsonResponse({'Status': False, 'Errors': 'Failed to authorize'}, status=status.HTTP_403_FORBIDDEN)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


class UserDetails(APIView):
    """
    Класс для работы данными пользователя
    """

    def get(self, request, *args, **kwargs):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if {'password'}.issubset(request.data):
            if 'password' in request.data:
                try:
                    validate_password(request.data['password'])
                except Exception as password_error:
                    return JsonResponse({'Status': False, 'Errors': {'password': password_error}},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                request.user.set_password(request.data['password'])

        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True}, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(ModelViewSet):
    queryset = ProductInfo.objects.all()
    serializer_class = ProductInfoSerializer
    http_method_names = ['get', ]
    """
    Класс для поиска товаров
    """

    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()
        serializer = ProductInfoSerializer(queryset, many=True)
        return Response(serializer.data)


class BasketView(APIView):
    """
    Класс для работы с корзиной пользователя
    """

    def get(self, request, *args, **kwargs):
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product_parameters__parameter').annotate(
             total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()
        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        items = request.data.get('items')
        if items:
            try:
                items_dict = json.dumps(items)
            except ValueError as e:
                JsonResponse({'Status': False, 'Errors': f'Invalid request format {e}'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id,
                                                        state='basket')
                objects_created = 0
                for order_item in load_json(items_dict):
                    order_item.update({'order': basket.id})
                    serializer = OrderItemSerializer(data=order_item)
                    if serializer.is_valid(raise_exception=True):
                        try:
                            serializer.save()
                        except IntegrityError as e:
                            return JsonResponse({'Status': False,
                                            'Errors': str(e)})
                        else:
                            objects_created += 1

                    else:
                        JsonResponse({'Status': False,
                                'Errors': serializer.errors})

                return JsonResponse({'Status': True,
                                'Objects created': objects_created},
                                status=status.HTTP_201_CREATED)
        return JsonResponse({'Status': False,
                        'Errors': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, *args, **kwargs):
        items_sting = request.data.get('items')
        if items_sting:
            try:
                items_dict = json.dumps(items_sting)
            except ValueError as e:
                JsonResponse({'Status': False, 'Errors': f'Invalid request format {e}'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id,
                                                        state='basket')
                objects_updated = 0
                for order_item in json.loads(items_dict):
                    if isinstance(order_item['id'], int) and isinstance(order_item['quantity'], int):
                        objects_updated += OrderItem.objects.filter(
                            order_id=basket.id,
                            product_info_id=order_item['id']) \
                            .update(
                            quantity=order_item['quantity'])

                return JsonResponse({'Status': True,
                                    'Objects created': objects_updated})

        return JsonResponse({'Status': False,
                            'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):

        items = request.data.get('items')
        if items:
            items_list = items.split(',')
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            query = Q()
            objects_deleted = False
            for order_item_id in items_list:
                if order_item_id.isdigit():
                    query = query | Q(order_id=basket.id, id=order_item_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = OrderItem.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Objects created': deleted_count}, status=status.HTTP_200_OK)
        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)

        url = request.data.get('url')
        if url:
            try:
                task = get_import.delay(request.user.id, url)
            except IntegrityError as e:
                return JsonResponse({'Status': False,
                                    'Errors': f'Integrity Error: {e}'})

            return JsonResponse({'Status': True}, status=status.HTTP_200_OK)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


class PartnerState(APIView):
    """
    Класс для работы со статусом поставщика
    """

    def get(self, request, *args, **kwargs):
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shop only'}, status=status.HTTP_403_FORBIDDEN)
        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True}, status=status.HTTP_200_OK)
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)})

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'})


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
    """

    def get(self, request, *args, **kwargs):

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'}, status=status.HTTP_403_FORBIDDEN)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        send_email.delay('Order status update', 'The order has been processed', request.user.email)
        return Response(serializer.data)


class ContactView(APIView):
    """
    Класс для работы с контактами покупателей
    """


    def get(self, request, *args, **kwargs):
        contact = Contact.objects.filter(user_id=request.user.id)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if {'city', 'street', 'phone'}.issubset(request.data):
            request.POST._mutable = True
            request.data.update({'user': request.user.id})
            serializer = ContactSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True}, status=status.HTTP_201_CREATED)
            else:
                JsonResponse({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                        status=status.HTTP_401_UNAUTHORIZED)

    def put(self, request, *args, **kwargs):
        if {'id'}.issubset(request.data):
            try:
                contact = get_object_or_404(Contact, pk=int(request.data["id"]))
            except ValueError:
                return JsonResponse(
                    {'Status': False, 'Error': 'Invalid field type ID.'}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ContactSerializer(contact, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True}, status=status.HTTP_200_OK)
            return JsonResponse({'Status': False, 'Error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        if {'items'}.issubset(request.data):
            for item in request.data["items"].split(','):
                try:
                    contact = get_object_or_404(Contact, pk=int(item))
                    contact.delete()
                except ValueError:
                    return JsonResponse({'Status': False, 'Error': 'Invalid argument type (items).'},
                                    status=status.HTTP_400_BAD_REQUEST)
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Error': f'There is no contact with ID{item}'},
                                    status=status.HTTP_400_BAD_REQUEST)
            return JsonResponse({'Status': True}, status=status.HTTP_200_OK)

        return JsonResponse({'Status': False, 'Error': 'All necessary arguments are not specified'},
                        status=status.HTTP_400_BAD_REQUEST)


class OrderView(APIView):
    """
    Класс для получения и размешения заказов пользователями
    """

    def get(self, request, *args, **kwargs):
        order = Order.objects.filter(
            user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity')* F('ordered_items__product_info__price'))
        ).distinct().order_by('-date')

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):

        if {'id', 'contact'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    is_updated = Order.objects.filter(
                        user_id=request.user.id, id=request.data['id']).update(
                        contact_id=request.data['contact'],
                        state='new')
                except IntegrityError as error:
                    return JsonResponse({'Status': False, 'Errors': f'The arguments are incorrectly specified {error}'},
                                        status=status.HTTP_400_BAD_REQUEST)
                else:
                    if is_updated:
                        send_email.delay('Order status update', 'The order has been formed ',
                                    request.user.email)
                        return JsonResponse({'Status': True}, status=status.HTTP_200_OK)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)
