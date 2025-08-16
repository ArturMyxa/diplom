from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from backend.models import User, Shop, Product, Category, ProductParameter, ProductInfo, Parameter, OrderItem, Order, \
    Contact, ConfirmEmailToken


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    model = User
    fieldsets = (
        (None, {'fields': ('email', 'password', 'type')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'company', 'position')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('id','email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('first_name', 'last_name')
    list_filter = ('last_name', 'is_staff')

@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    model = Shop
    fieldsets = (
        (None, {'fields': ('name', 'state')}),
        ('Additional Info', {'fields': ('url', 'user')}),
    )
    list_display = ('id','name', 'state', 'url')
    search_fields = ('name',)
    list_filter = ('state',)
    list_editable = ('state',)

class ProductInline(admin.TabularInline):
    model = Product
    extra = 1


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    model = Category
    inlines = [ProductInline]


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    search_fields = ('name','category')

class ProductParameterInline(admin.TabularInline):
    model = ProductParameter
    extra = 1


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    model = ProductInfo
    fieldsets = (
        (None, {'fields': ('product', 'model', 'external_id', 'quantity', 'shop')}),
        ('Цены', {'fields': ('price', 'price_rrc')}),
    )
    list_display = ('id','product','external_id', 'price', 'price_rrc', 'quantity', 'shop')
    list_filter = ('model',)
    inlines = [ProductParameterInline]


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    pass


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    pass


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 1


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    model = Order
    fields = ('user', 'state', 'contact', 'date')
    list_display = ('id', 'user', 'date', 'state')
    inlines = [OrderItemInline,]


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    pass


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('id', 'city', 'phone')
    search_fields = ('city',)

@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'key', 'created_at',)
    search_fields = ('user',)
    list_filter = ('created_at',)